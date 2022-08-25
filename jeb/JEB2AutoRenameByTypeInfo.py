# -*- coding: utf-8 -*-  
  
import string
import re,collections
from java.lang import Runnable
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit


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

    # rename class
    for clz in dexUnit.getClasses():
      className = clz.getName(False)
      if len(className) == 0:
        continue

      if not self.isObfName(className):
        continue

    # rename method
    for method in dexUnit.getMethods():
      methodName = method.getName(False)
      if len(methodName) == 0:
        continue
      #print(methodName)

    # rename field
    for field in dexUnit.getFields():
      fieldName = field.getName(False)
      if len(fieldName) == 0:
        continue
      print(fieldName)

  pass



  def isObfName(self, className):

    # if className[0] == 'db':
    #   print(className)
    #   print(className[0])
    return True

