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
    _pcode = None
    pcode_iterator = block.getIterator()
    while pcode_iterator.hasNext():
        _pcode = pcode_iterator.next()
    return _pcode


# 获取状态变量
def getStateVarnode(func, addr):
    pcode_iterator = func.getPcodeOps(addr)
    _pcode = None

    # find the pcode for COPYing const
    while pcode_iterator.hasNext():
        _pcode = pcode_iterator.next()
        if _pcode.getOpcode() == PcodeOp.COPY and _pcode.getInput(0).isConstant():
            break
    logging.info('COPY const pcode: %s' % _pcode)

    # find the state var in phi node
    depth = 0
    while _pcode is not None and _pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.info('finding phi node: %s, depth %d' % (_pcode, depth))
        if _pcode.getOutput() is None:
            logging.warning('output is None in %s' % _pcode)
            break
        # if there is only one PcodeOp taking this varnode as input then return it
        _pcode = _pcode.getOutput().getLoneDescend()
        if depth > 5:
            break
        depth += 1

    if _pcode is None or _pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.warning('cannot find phi node')
        return None
    else:
        logging.info('phi node: %s' % _pcode)

    _stateVarnode = _pcode.getOutput()
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
        # defVar = cmpVar.getDef()
        logging.warning('cmpVar is unknow')
        return False
    return stateVar.getAddress() == cmpVar.getAddress()


# 获取状态变量与真实块之间的映射
def getConstantBlockMap(stateVar, blockList):
    _ConstantBlockMap = {}
    for i in range(0, len(blockList)):
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
            logging.warning('[getStateMap] not const var in %s' % blockList[i])
            continue

        if isStateVarnode(stateVar, comparedVar):
            if conditionType == PcodeOp.INT_NOTEQUAL:
                dstBlock = blockList[i].getFalseOut()
            else:
                dstBlock = blockList[i].getTrueOut()
            # `<地址空间、偏移量、大小>`
            if dstBlock == blockList[1]:
                _ConstantBlockMap[blockList[i]] = constVar.getOffset()
                # _ConstantBlockMap[constVar.getOffset()] = blockList[i]  # 有些block的dstBlock 是主分发器
            else:
                # _ConstantBlockMap[constVar.getOffset()] = dstBlock
                _ConstantBlockMap[dstBlock] = constVar.getOffset()
        else:
            logging.warning(blockList[i])
    return _ConstantBlockMap


# 定位状态变量更新的block
def getStateUpdateMap(stateVar):
    _stateUpdateMap = {}
    phiNode = stateVar.getDef()
    inputList = list(set(phiNode.getInputs()))
    _count = 1
    for in0 in inputList:
        parentBlock = in0.getDef().getParent()
        _pcode = in0.getDef().getInput(0).getDef()
        if _pcode.getInput(0).getDef() == stateVar:
            continue

        if _pcode.getOpcode() == PcodeOp.COPY and _pcode.getInput(0).isConstant():
            _stateUpdateMap[parentBlock] = _pcode.getInput(0).getOffset()
    return _stateUpdateMap


# value of state var may need to be updated before compared to const
def constUpdate(const):
    # signed to unsigned
    return const & 0xffffffff


def gen_cfg(updateMap, constMap):
    links = []
    cmovbb = []  # basic blocks for CMOVXX

    for def_block, const in updateMap.items():
        # unconditional jump
        link = None
        if def_block.getOutSize() == 1:
            for _block, _const in constMap.items():
                if const == _const:
                    link = (def_block, constMap[_block])
                    logging.info('unconditional jump link: %s' % str(link))
                    links.append(link)
            if not link:
                logging.warning('cannot find const 0x%x in const_map' % const)

        elif def_block.getOutSize() == 2:
            logging.info('conditional jump block: %s' % def_block)
    pass


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
        logging.info("currentProgram      : %s" % currentProgram.toString())
        logging.info("currentAddress      : %s" % currentAddress.toString())
        logging.info("currentFunction     : %s" % currentFunction.toString())
        logging.info("decompileRes        : %s" % decompileRes.toString())
        logging.info("currentHighFunction : %s" % currentHighFunction.toString())

    '''
    获取序言块和主分发器
    '''
    blocks = currentHighFunction.getBasicBlocks()
    prologueBlock = blocks[0]
    mainDispatcherBlock = blocks[1]
    logging.info("prologueBlock       : %s" % prologueBlock.toString())
    logging.info("mainDispatcherBlock : %s" % mainDispatcherBlock.toString())

    '''
    定位状态变量
    COPYing const 只是临时变量
    pcode遵循SSA规则，每个变量只能赋值一次，若变量需要多次赋值，则使用phi node进行处理
    MULTIEQUAL 对应 phi node
    '''
    stateVarnode = getStateVarnode(currentHighFunction, currentAddress)
    if not stateVarnode:
        logging.warning("getStateVarnode error!")
        exit()
    logging.info('[stateVarnode] is %s' % stateVarnode)

    '''
    获取状态变量与真实块之间的映射
    '''
    constantBlockMap = getConstantBlockMap(stateVarnode, blocks)
    if len(constantBlockMap) < 1:
        logging.warning("getStateMap error!")
        exit()
    count = 1
    for key in constantBlockMap:
        logging.info('[%d]stateMap:block=[%s] -> const=[0x%08x]' % (count, key, constantBlockMap[key]))
        count += 1

    '''
    定位状态变量更新的block
    '''
    stateUpdateMap = getStateUpdateMap(stateVarnode)
    if len(stateUpdateMap) < 1:
        logging.warning("getStateUpdateMap error!")
        exit()
    count = 1
    for key in stateUpdateMap:
        logging.info('[%d]stateUpdateMap:block=[%s] -> const=[0x%08x]' % (count, key, stateUpdateMap[key]))
        count += 1

    # FUN_00119cc8
    gen_cfg(stateUpdateMap, constantBlockMap)
    '''
    patch代码
    '''
    # for const in stateUpdateMap:
    #     pcode = getLastPcode(stateUpdateMap[const])
    #     if pcode.getOpcode() == PcodeOp.BRANCH:
    #         dstBlock = None
    #         for key in stateMap:
    #             if key == const:
    #                 dstBlock = stateMap[key]
    #                 break
    #         if not dstBlock:
    #             continue
