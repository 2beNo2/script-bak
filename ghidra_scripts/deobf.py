# coding=utf-8
# @category OLLVM

import os
import binascii
import logging

try:
    from ghidra.ghidra_builtins import *
except:
    pass

from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.mem import *
from ghidra.app.plugin.assembler import Assemblers

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s][%(levelname)s] - %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S %p')


# 获取块中最后一条pcode
def getLastPcode(block):
    pcode = None
    pcode_iterator = block.getIterator()
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
    return pcode


# 获取状态变量
def getStateVarnode(func, addr):
    iterator = func.getPcodeOps(addr)
    pcode = None

    # find the pcode for COPYing const
    while iterator.hasNext():
        pcode = iterator.next()
        if pcode.getOpcode() == PcodeOp.COPY and pcode.getInput(0).isConstant():
            break
    logging.info('COPY const pcode: %s' % pcode)

    # find the state var in phi node
    depth = 0
    while pcode is not None and pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.info('finding phi node: %s, depth %d' % (pcode, depth))
        if pcode.getOutput() is None:
            logging.warning('output is None in %s' % pcode)
            break
        # if there is only one PcodeOp taking this varnode as input then return it
        pcode = pcode.getOutput().getLoneDescend()
        if depth > 5:
            break
        depth += 1

    if pcode is None or pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.warning('cannot find phi node')
        return None
    else:
        logging.info('phi node: %s' % pcode)

    _stateVarnode = pcode.getOutput()
    logging.info('state varnode is %s' % _stateVarnode)
    return _stateVarnode


# check is state varnode
def isStateVarnode(stateVar, cmpVar):
    if cmpVar.isUnique():
        # defVar = cmpVar.getDef()
        logging.warning('cmpVar is Unique')
        return False
    elif cmpVar.isRegister():
        defVar = cmpVar.getDef()
        if defVar.getOpcode() == PcodeOp.COPY:
            cmpVar = defVar.getInput(0)
    else:
        defVar = cmpVar.getDef()
        # logging.warning('cmpVar = %s defVar = %s' % (cmpVar, defVar))
        return False
    return stateVar.getAddress() == cmpVar.getAddress()


# 获取状态变量与真实块之间的映射
def getStateMap(stateVar, blockList):
    stateMap = {}
    for i in range(2, len(blockList)):
        if blockList[i].getOutSize() != 2:
            continue

        lastPcode = getLastPcode(blockList[i])
        if lastPcode.getOpcode() != PcodeOp.CBRANCH:
            continue

        # check is INT_NOTEQUAL or INT_EQUAL
        condition = lastPcode.getInput(1)
        conditionPcode = condition.getDef()
        conditionType = conditionPcode.getOpcode()
        if not conditionType in (PcodeOp.INT_NOTEQUAL, PcodeOp.INT_EQUAL):
            continue

        # check is have constant
        in0 = conditionPcode.getInput(0)
        in1 = conditionPcode.getInput(1)
        constVar = None
        comparedVar = None
        if in0.isConstant():
            constVar = in0
            comparedVar = in1
        elif in1.isConstant():
            constVar = in1
            comparedVar = in0
        else:
            logging.warning('not const var in %s' % conditionPcode)
            continue
        # logging.info("lastPcode  : %s" % lastPcode)
        # logging.info("conditionPcode  : %s" % conditionPcode)

        if isStateVarnode(stateVar, comparedVar):
            if conditionType == PcodeOp.INT_NOTEQUAL:
                dstBlock = blockList[i].getFalseOut()
            else:
                dstBlock = blockList[i].getTrueOut()
            # `<地址空间、偏移量、大小>`
            # logging.info("getOffset  : %s" % constVar.getOffset())
            stateMap[constVar.getOffset()] = dstBlock
        else:
            logging.warning(blockList[i])
            # pcode_iterator = blocks[i].getIterator()
            # while pcode_iterator.hasNext():
            #     pcode = pcode_iterator.next()
            #     logging.info(pcode)

    return stateMap


if __name__ == '__main__':
    '''
    1、函数的开始地址为序言（Prologue）的地址
    2、序言的后继为主分发器（Main dispatcher）
    3、后继为主分发器的块为预处理器（Predispatcher）
    4、后继为预处理器的块为真实块（Relevant blocks）
    5、无后继的块为retn块
    6、剩下的为无用块与子分发器（Sub dispatchers）
    '''

    '''
    init
    '''
    decompLib = DecompInterface()
    decompLib.openProgram(currentProgram)

    currentFunction = getFunctionContaining(currentAddress)
    decompileRes = decompLib.decompileFunction(currentFunction, 1200, getMonitor())
    currentHighFunction = decompileRes.getHighFunction()
    if currentHighFunction is None:
        logging.warning("decompileFunction error : %s" % decompileRes.getErrorMessage())
        exit()
    else:
        logging.info("currentProgram  : %s" % currentProgram.toString())
        logging.info("currentAddress  : %s" % currentAddress.toString())
        logging.info("currentFunction : %s" % currentFunction.toString())
        logging.info("decompileRes    : %s" % decompileRes.toString())
        logging.info("currentHighFunction : %s" % currentHighFunction.toString())

    '''
    获取序言块和主分发器
    '''
    blocks = currentHighFunction.getBasicBlocks()
    prologueBlock = blocks[0]
    mainDispatcherBlock = blocks[1]
    logging.info("prologueBlock : %s" % prologueBlock.toString())
    logging.info("mainDispatcherBlock : %s" % mainDispatcherBlock.toString())

    '''
    定位状态变量
    COPYing const 只是临时变量
    pcode遵循SSA，每个变量只能赋值一次，若变量需要多次赋值，则使用phi node进行处理
    MULTIEQUAL 对应 phi node
    '''
    stateVarnode = getStateVarnode(currentHighFunction, currentAddress)
    if not stateVarnode:
        logging.warning("getStateVarnode error!")
        exit()

    '''
    获取状态变量与真实块之间的映射
    '''
    stateMap = getStateMap(stateVarnode, blocks)
    if len(stateMap) < 1:
        logging.warning("getStateMap error!")
        exit()
    count = 1
    for key in stateMap:
        logging.info('%d:%x -> %s' % (count, key, stateMap[key]))
        count += 1

    '''
    获取真实块
    观察CFG，没有预处理器，将后继为主分发器的块都视为真实块
    '''
    for i in range(2, len(blocks)):
        for j in range(blocks[i].getOutSize()):
            if blocks[i].getOut(j) == mainDispatcherBlock:
                # if blocks[i].getOutSize() > 1:
                #     pcode = get_last_pcode(blocks[i])
                #     logging.info("block : %s, pcode : %s" % (blocks[i].toString(), pcode))

                pcode_iterator = blocks[i].getIterator()
                while pcode_iterator.hasNext():
                    pcode = pcode_iterator.next()
                    # logging.info(pcode)
