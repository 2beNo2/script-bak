#coding=utf-8


#@category    Analysis.deobf



import os
import binascii
import logging

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.mem import *
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.plugin.assembler import Assemblers

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s][%(levelname)s] - %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S %p')


# 获取块中最后一条pcode
def get_last_pcode(block):
    pcode_iterator = block.getIterator()
    while pcode_iterator.hasNext():
        pcode = pcode_iterator.next()
        if not pcode_iterator.hasNext():
            return pcode


# 获取真实块
def get_real_block(blocks):
    for block in blocks:
        pcode =  get_last_pcode(block)
        if pcode.getOpcode() == PcodeOp.BRANCH:
            logging.info("block = %s, Parent = %s" %(block.toString(), block.getIn(0).toString()))



if __name__ == '__main__':
    # init
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)

    current_function = getFunctionContaining(currentAddress)
    decompile_res = decomplib.decompileFunction(current_function, 1200, getMonitor())
    high_function = decompile_res.getHighFunction()

    '''
    1、函数的开始地址为序言（Prologue）的地址
    2、序言的后继为主分发器（Main dispatcher）
    3、后继为主分发器的块为预处理器（Predispatcher）
    4、后继为预处理器的块为真实块（Relevant blocks）
    5、无后继的块为retn块
    6、剩下的为无用块与子分发器（Sub dispatchers）
    '''

    # 获取序言块和主分发器
    blocks = high_function.getBasicBlocks()
    prologue_block = blocks[0]
    dispatcher_block = blocks[1]
    logging.info("prologue_block : %s" % prologue_block.toString())
    logging.info("dispatcher_block : %s" % dispatcher_block.toString())

    for i in range(2, len(blocks)):
        logging.info("[%d]block : %s block_out : %d" % (i, blocks[i].toString(), blocks[i].getOutSize()))
 
    
    # for block in blocks:
    #     pcode =  get_last_pcode(block)
    #     if pcode.getOpcode() == PcodeOp.BRANCH:
    #         if block.getInSize() == 1:
    #             block_prev = block.getIn(0)
    #             logging.info(block)
    #             logging.info(block_prev)

    #             pcode_iterator = block_prev.getIterator()
    #             while pcode_iterator.hasNext():
    #                     pcode = pcode_iterator.next()
    #                     logging.info(pcode)


