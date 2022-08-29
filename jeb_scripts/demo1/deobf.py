# -*- coding: utf-8 -*-

import sys
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units.code import ICodeItem
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaAssignment, IJavaStaticField, IJavaNewArray, IJavaReturn, IJavaCall, \
  IJavaClass, IJavaField, IJavaMethod, IJavaConstant, IJavaArithmeticExpression, IJavaIdentifier, IJavaDefinition
from com.pnfsoftware.jeb.core.actions import ActionXrefsData, ActionContext, Actions
from com.pnfsoftware.jeb.core.events import JebEvent, J


def getHashCode(s):
  h = 0
  for c in s:
    h = int((((31 * h + ord(c)) ^ 0x80000000) & 0xFFFFFFFF) - 0x80000000)
  return h


class deobf(IScript):
  def run(self, ctx):
    prj = ctx.getMainProject()
    self.dexUnit = prj.findUnit(IDexUnit)
    self.javaSourceUnit = prj.findUnits(IJavaSourceUnit)
    self.classList = []
    self.encryptBytes = []
    self.hashFunName = None
    self.keys = dict()

    for unit in self.javaSourceUnit:
      """
      IJavaConstantFactory --> Builder for Java AST constants.
        Get an AST element builder. 
        The builder is used to create new AST elements, 
        which can then be inserted in an existed AST
      """
      self.cstbuilder = unit.getFactories().getConstantFactory()
      javaClass = unit.getClassElement()
      self.getAllClasses(javaClass)
      for clz in self.classList:
        if self.isNeedDeobf(clz):
          self.encryptBytes = self.getShortData(clz)
          for javaMethod in clz.getMethods():
            self.obfstr2Hash(javaMethod)
            unit.notifyListeners(JebEvent(J.UnitChange))

          for javaMethod in clz.getMethods():
            self.doDecrypt(javaMethod)
            unit.notifyListeners(JebEvent(J.UnitChange))
    print("deobf done!")


  def getAllClasses(self, javaClass):
    classList = []
    classList.append(javaClass)
    stack = [javaClass]
    while len(stack) != 0:
      cur_class = stack.pop()

      #inner class
      inner_class_list = cur_class.getInnerClasses()  
      for inner_class in inner_class_list:
        classList.append(inner_class)
        stack.append(inner_class)

      # Anonymous Class
      inner_class_list = cur_class.getAnonymousClasses()  
      for inner_class in inner_class_list:
        classList.append(inner_class)
        stack.append(inner_class)

      for method in cur_class.getMethods(): 
        inner_class_list = method.getInnerClasses()
        for inner_class in inner_class_list:
          classList.append(inner_class)
          stack.append(inner_class)

        inner_class_list = method.getAnonymousClasses()
        for inner_class in inner_class_list:
          classList.append(inner_class)
          stack.append(inner_class)
    self.classList = list(set(classList))   


  def isNeedDeobf(self, javaClass):
    wanted_flags = ICodeItem.FLAG_PRIVATE|ICodeItem.FLAG_STATIC|ICodeItem.FLAG_FINAL
    f = None

    #check is shortArray
    for javaField in javaClass.getFields():
      fsig = javaField.getSignature()
      if fsig.endswith(':[S') and fsig.find('short') >= 0: 
        f = self.dexUnit.getField(fsig)
        if f and f.getGenericFlags() & wanted_flags == wanted_flags:
          break
    if not f:
      return False

    for method in javaClass.getMethods():
      if not method.isStatic():
        continue
      sig = method.getSignature()
      if sig.find('(Ljava/lang/Object;)I') > 0 and self.getXrefNum(sig) > 2:
        block = method.getBody()
        if isinstance(block.get(0), IJavaReturn):
          self.hashFunName = method.getName()
    if self.hashFunName == None:
      return False
    return True


  def getXrefNum(self, sig):
    method = self.dexUnit.getMethod(sig)
    actionXrefsData = ActionXrefsData()
    actionContext = ActionContext(self.dexUnit, Actions.QUERY_XREFS, method.getItemId(), None)
    if self.dexUnit.prepareExecution(actionContext,actionXrefsData):
      xref_addr = actionXrefsData.getAddresses()
      return len(xref_addr)


  def getShortData(self, javaClass):
    encryptBytes = []
    for method in javaClass.getMethods():
      if method.getName() == '<clinit>':
        for i in range(method.getBody().size()):
          statement = method.getBody().get(i) # return IStatement

          # xxx.short = new short[]{...}
          if isinstance(statement, IJavaAssignment):
            if isinstance(statement.getLeft(), IJavaStaticField):
              fsig = statement.getLeft().getFieldSignature()
              if fsig.endswith(':[S') and fsig.find('short') >= 0:
                array = statement.getRight()
                if isinstance(array, IJavaNewArray):
                  for v in array.getInitialValues():
                    encryptBytes.append(v.getShort())
                  return encryptBytes


  def obfstr2Hash(self, javaMethod):
    block = javaMethod.getBody()
    i = 0
    while i < block.size():
      statement = block.get(i)  # IStatement
      self.replaceStr2HashCode(block, statement)
      i += 1


  def replaceStr2HashCode(self, parent, e):
    if isinstance(e, IJavaCall): 
      if e.getMethod().getName() == self.hashFunName:
        v = []
        for arg in e.getArguments():
          if isinstance(arg, IJavaConstant):
            v.append(arg.getString())
          else:
            return
        if len(v) == 1:
          hash_code = getHashCode(v[0])
          parent.replaceSubElement(e, self.cstbuilder.createInt(hash_code))   

    for subelt in e.getSubElements():  
      if isinstance(subelt, IJavaClass) or isinstance(subelt, IJavaField) or isinstance(subelt, IJavaMethod):
        continue
      self.replaceStr2HashCode(e, subelt)


  def doDecrypt(self, javaMethod):
    block = javaMethod.getBody()
    i = 0
    while i < block.size():
      stm = block.get(i)  # IStatement
      self.callDecryptStrFun(block, stm)
      i += 1


  def callDecryptStrFun(self, parent, e):
    if isinstance(e, IJavaAssignment) and e.isSimpleAssignment(): 
      left = e.getLeft()
      right = e.getRight()

      # JavaArithmeticExpression 算术表达式
      if isinstance(right, IJavaArithmeticExpression) and str(right.getOperator()) == '^':
        if isinstance(right.getLeft(), IJavaConstant) and isinstance(right.getRight(), IJavaConstant):
          op1 = right.getLeft().getInt()
          op2 = right.getRight().getInt()
          self.keys[left.getIdentifier().getName()] = 0xffffffff & (op1 ^ op2)
      elif isinstance(right, IJavaConstant) and isinstance(left, IJavaDefinition):
        # 可能第四个参数处理方式不同
        # int v1 = 0x12345; int v1 是IJavaDefinition
        #print(type(left))
        self.keys[left.getIdentifier().getName()] = right.getInt()

    elif isinstance(e, IJavaCall): 
      sig = e.getMethodSignature()
      if sig.find('(Ljava/lang/Object;III)Ljava/lang/String;') > 0:
        v = []
        for arg in e.getArguments():
          v.append(arg)
        if len(v) == 4:
          arg1 = -1
          arg2 = -1
          if isinstance(v[1].getLeft(), IJavaConstant) and isinstance(v[1].getRight(), IJavaConstant):
            op1 = v[1].getLeft().getInt()
            op2 = v[1].getRight().getInt()
            arg1 = 0xffffffff & (op1 ^ op2)
          if isinstance(v[2].getLeft(), IJavaConstant) and isinstance(v[2].getRight(), IJavaConstant):
            op1 = v[2].getLeft().getInt()
            op2 = v[2].getRight().getInt()
            arg2 = 0xffffffff & (op1 ^ op2)
          if isinstance(v[3], IJavaIdentifier):
            arg3 = self.keys[v[3].getName()]

          if arg1 == -1 or arg2 == -1 or arg3 == -1:
            return

          decrypt_string = self.decrypt(arg1, arg2, arg3)
          print("decrypt_string =", decrypt_string)
          parent.replaceSubElement(e, self.cstbuilder.createString(decrypt_string))

    for subelt in e.getSubElements():
      if isinstance(subelt, IJavaClass) or isinstance(subelt, IJavaField) or isinstance(subelt, IJavaMethod):
        continue
      self.callDecryptStrFun(e, subelt)       


  def decrypt(self, base, size, key):
    out = ''
    for i in range(size):
      out += chr(0xff & (self.encryptBytes[base + i] ^ key))
    return out

   