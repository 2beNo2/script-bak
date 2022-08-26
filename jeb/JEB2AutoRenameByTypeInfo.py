# -*- coding: utf-8 -*-  
  
import string
import re,collections
from java.lang import Runnable
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from com.pnfsoftware.jeb.core.actions import ActionRenameData, ActionContext, Actions

class JEB2AutoRenameByTypeInfo(IScript):  
  def run(self, ctx):  # ctx -> IClientContext
    ctx.executeAsync("Running name detection...", JEB2AutoRename(ctx))   
    print('Done Ok!')


class JEB2AutoRename(Runnable):
  def __init__(self, ctx):
    self.ctx = ctx

  def run(self):
    ctx = self.ctx
    prj = ctx.getMainProject()
    if not prj:
      print('There is no opened project')
      return
  
    dexUnit = prj.findUnit(IDexUnit)
    self.dexUnit = dexUnit

    # rename class
    for clz in dexUnit.getClasses():
      className = clz.getName(False)
      if len(className) == 0:
        continue
      if self.isObfName(className):
        newName = self.getNewName(clz, 0)
        self.doRename(clz, newName)

    # rename method
    for method in dexUnit.getMethods():
      methodName = method.getName(False)
      if len(methodName) == 0:
        continue
      if self.isObfName(methodName):
        newName = self.getNewName(method, 1)
        self.doRename(method, newName)

    # rename field
    for field in dexUnit.getFields():
      fieldName = field.getName(False)
      if len(fieldName) == 0:
        continue
      if self.isObfName(fieldName):
        newName = self.getNewName(field, 2)
        self.doRename(field, newName)

  def doRename(self, obj, newName):
    actCntx = ActionContext(self.dexUnit, Actions.RENAME, obj.getItemId(), obj.getAddress()) 
    actData = ActionRenameData()  
    actData.setNewName(newName)   
    if(self.dexUnit.prepareExecution(actCntx, actData)): 
      self.dexUnit.executeAction(actCntx, actData)

  def getNewName(self, obj, isClass):
    if isClass == 0:
      clzIndex = str(obj.getIndex())
      clzAddress = obj.getAddress()
      clzAddress = clzAddress[0:clzAddress.rfind('/')]
      newName = clzAddress[clzAddress.rfind('/')+1:-1] + clzIndex
    elif isClass == 1:
      methodIndex = str(obj.getIndex())
      newName = 'param_' + ''.join(map(lambda x: x.getName(True), obj.getParameterTypes())) + methodIndex
    else:
      fieldIndex = str(obj.getIndex())
      newName = obj.getFieldType().getName(True) + '_' + fieldIndex
    return newName

  # check name
  def isObfName(self, str):
    if ord(str[0]) >= 33 and ord(str[0]) <= 122:
      return False
    return True







