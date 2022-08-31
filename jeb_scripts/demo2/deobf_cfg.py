# -*- coding: utf-8 -*-

import sys
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units.code import ICodeItem
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaAssignment, IJavaStaticField, IJavaNewArray, IJavaReturn, IJavaCall, \
  IJavaClass, IJavaField, IJavaMethod, IJavaConstant, IJavaArithmeticExpression, IJavaIdentifier, IJavaDefinition
from com.pnfsoftware.jeb.core.actions import ActionXrefsData, ActionContext, Actions
from com.pnfsoftware.jeb.core.events import JebEvent, J



class deobf_cfg(IScript):
  def run(self, ctx):
    prj = ctx.getMainProject()
    self.dexUnit = prj.findUnit(IDexUnit)
    self.javaSourceUnit = prj.findUnits(IJavaSourceUnit)
    self.classList = []
    self.encryptBytes = []
    self.hashFunName = None
    self.keys = dict()

    # rename method
    for method in self.dexUnit.getMethods():
      methodName = method.getName(False)
      if len(methodName) == 0:
        continue
      if self.isObfName(methodName):
        dexMethodData = method.getData(); 
        if dexMethodData == None:
          continue
        dexCodeItem= dexMethodData.getCodeItem();
        if dexCodeItem == None:
          continue

        # 控制流图
        print("-------------------------------------")
        print method
        cfg = dexCodeItem.getControlFlowGraph()
        print "01 Block               >>> ",cfg.getBlocks()             # 基本快列表
        print "02 size                >>> ",cfg.size()                  # 块个数
        print "03 hasExit             >>> ",cfg.hasExit()               # 是否有出口
        print "04 getEntryBlock       >>> ",cfg.getEntryBlock()         # 入口块
        print "05 getExitBlocks       >>> ",cfg.getExitBlocks()         # 出口块(不唯一)
        print "06 getLast             >>> ",cfg.getLast()               # 最后一个块
        print "07 getAddressBlockMap  >>> ",cfg.getAddressBlockMap()    # map<偏移地址,块>
        print "08 getEndAddress       >>> ",hex(cfg.getEndAddress())    # 结尾指令地址
        print "09 formatEdges         >>> ",cfg.formatEdges()           # 输出边(字符串)

  # check name
  def isObfName(self, str):
    if ord(str[0]) >= 33 and ord(str[0]) <= 122:
      return False
    return True



