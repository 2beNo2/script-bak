# coding=utf-8
#@category OLLVM

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
def get_last_pcode(block):
    pcode = None
    pcode_iterator = block.getIterator()
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
    return pcode


# 获取真实块
def get_real_block(blocks):
    for block in blocks:
        pCode = get_last_pcode(block)
        if pCode.getOpcode() == PcodeOp.BRANCH:
            logging.info("block = %s, Parent = %s" % (block.toString(), block.getIn(0).toString()))


def get_state_var(high_function, current_address):
    pcode_iterator = high_function.getPcodeOps(current_address)
    pcode = None

    # find the pcode for COPYing const
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        logging.debug('finding COPY const pcode: %s' % pcode)
        if pcode.getOpcode() == PcodeOp.COPY and pcode.getInput(0).isConstant():
            break

    logging.info('COPY const pcode: %s' % pcode)

    # find the state var in phi node
    depth = 0
    while pcode is not None and pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.debug('finding phi node: %s, depth %d' % (pcode, depth))
        if pcode.getOutput() is None:
            logging.warning('output is None in %s' % pcode)
            break
        pcode = pcode.getOutput().getLoneDescend()
        if depth > 5:
            break
        depth += 1

    if pcode is None or pcode.getOpcode() != PcodeOp.MULTIEQUAL:
        logging.error('cannot find phi node')
        return None
    else:
        logging.info('phi node: %s' % pcode)

    state_var = pcode.getOutput()
    logging.info('state var is %s' % state_var)
    return state_var


if __name__ == '__main__':
    '''
    1、函数的开始地址为序言（Prologue）的地址
    2、序言的后继为主分发器（Main dispatcher）
    3、后继为主分发器的块为预处理器（Predispatcher）
    4、后继为预处理器的块为真实块（Relevant blocks）
    5、无后继的块为retn块
    6、剩下的为无用块与子分发器（Sub dispatchers）
    '''

    # init
    decompLib = DecompInterface()
    decompLib.openProgram(currentProgram)

    current_function = getFunctionContaining(currentAddress)
    decompile_res = decompLib.decompileFunction(current_function, 1200, getMonitor())
    high_function = decompile_res.getHighFunction()
    if high_function is None:
        logging.info("decompileFunction error : %s" % decompile_res.getErrorMessage())
        exit()
    else:
        logging.info("currentProgram : %s" % currentProgram.toString())
        logging.info("currentAddress : %s" % currentAddress.toString())
        logging.info("current_function : %s" % current_function.toString())
        logging.info("decompile_res : %s" % decompile_res.toString())
        logging.info("high_function : %s" % high_function.toString())

    '''
    获取序言块和主分发器
    '''
    blocks = high_function.getBasicBlocks()
    prologue_block = blocks[0]
    main_dispatcher_block = blocks[1]
    logging.info("prologue_block : %s" % prologue_block.toString())
    logging.info("main_dispatcher_block : %s" % main_dispatcher_block.toString())

    '''
    定位状态变量
    '''
    pcode = None
    pcode_iterator = prologue_block.getIterator()
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        if pcode.getOpcode() == PcodeOp.COPY and pcode.getInput(0).isConstant():
            logging.info("pcode : %s" % pcode.toString())

    if not pcode:
        logging.info("find varnode_pcode error!")
        exit()

    pcode_iterator = prologue_block.getIterator()
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        logging.info("pcode : %s" % pcode.toString())
    # depth = 0
    # while pcode is not None and pcode.getOpcode() != PcodeOp.MULTIEQUAL:
    #     logging.debug('finding phi node: %s, depth %d' % (pcode, depth))
    #     if pcode.getOutput() is None:
    #         logging.warning('output is None in %s' % pcode)
    #         break
    #     pcode = pcode.getOutput().getLoneDescend()
    #     if depth > 5:
    #         break
    #     depth += 1


    '''
    获取真实块
    观察CFG，没有预处理器，将后继为主分发器的块都视为真实块
    '''
    # for i in range(2, len(blocks)):
    #     logging.info("[%d]block : %s block_out : %d" % (i, blocks[i].toString(), blocks[i].getOutSize()))

    # for block in blocks:
    #     pcode =  get_last_pcode(block)
    #     if pcode.getOpcode() == PcodeOp.BRANCH:
    #         if block.getInSize() == 1:
    #             block_prev = block.getIn(0)
    #             logging.info(block)
    #             logging.info(block_prev)
    #
    #             pcode_iterator = block_prev.getIterator()
    #             while pcode_iterator.hasNext():
    #                     pcode = pcode_iterator.next()
    #                     logging.info(pcode)

    # for i in range(2, len(blocks)):
    #     for j in range(blocks[i].getOutSize()):
    #         if blocks[i].getOut(j) == main_dispatcher_block:
    #             if blocks[i].getOutSize() > 1:
    #                 pcode = get_last_pcode(blocks[i])
    #                 logging.info("block : %s, pcode : %s" % (blocks[i].toString(), pcode))
    #
    #                 pcode_iterator = blocks[i].getIterator()
    #                 while pcode_iterator.hasNext():
    #                     pcode = pcode_iterator.next()
    #                     logging.info(pcode)