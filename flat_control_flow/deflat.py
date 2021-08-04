#!/usr/bin/env python3

import sys
sys.path.append("..")

import argparse
import angr
import pyvex
import claripy
import struct
from collections import defaultdict

import am_graph
from util import *

import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
# logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

def get_relevant_nop_nodes(supergraph, pre_dispatcher_node, prologue_node, ret_nodes):
    # relevant_nodes = list(supergraph.predecessors(pre_dispatcher_node))
    relevant_nodes = []
    nop_nodes = []
    for node in supergraph.nodes():
        if supergraph.has_edge(node, pre_dispatcher_node) and node.size > 8:
            # XXX: use node.size is faster than to create a block
            relevant_nodes.append(node)
            continue
        if node.addr in (prologue_node.addr, pre_dispatcher_node.addr):
            continue
        if node.addr in [node.addr for node in ret_nodes]:
            continue
        nop_nodes.append(node)
    return relevant_nodes, nop_nodes


def symbolic_execution(project, relevant_block_addrs, start_addr, hook_addrs=None, modify_value=None, inspect=False):
    def retn_procedure(state):
        ip = state.solver.eval(state.regs.ip)
        project.unhook(ip)
        return

    def statement_inspect(state):
        expressions = list(
            state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    if hook_addrs is not None:
        skip_length = 4
        if project.arch.name in ARCH_X86:
            skip_length = 5

        for hook_addr in hook_addrs:
            project.hook(hook_addr, retn_procedure, length=skip_length)

    state = project.factory.blank_state(addr=start_addr, remove_options={
                                        angr.sim_options.LAZY_SOLVES})
    if inspect:
        state.inspect.b(
            'statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    sm = project.factory.simulation_manager(state)
    sm.step()
    while len(sm.active) > 0:
        for active_state in sm.active:
            if active_state.addr in relevant_block_addrs:
                return active_state.addr
        sm.step()

    return None

def main(target_function):
    # Note that our function can't tell whether this function has been flated!!!
    start = target_function.addr
    # A super transition graph is a graph that looks like IDA Pro's CFG
    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    # get prologue_node and ret_nodes
    prologue_node = None
    ret_nodes = []
    for node in supergraph.nodes():
        if supergraph.in_degree(node) == 0:
            prologue_node = node
        # [-] Not ferfect !
        if supergraph.out_degree(node) == 0:
            ret_nodes.append(node)

    if prologue_node is None or prologue_node.addr != start:
        print("Cant find prologue node...")
        return False

    main_dispatcher_node = list(supergraph.successors(prologue_node))[0]
    for node in supergraph.predecessors(main_dispatcher_node):
        if node.addr != prologue_node.addr and node.addr != main_dispatcher_node.addr:
            pre_dispatcher_node = node
            break

    if pre_dispatcher_node is None:
        print("Cant find pre_dispatcher node...")
        return False
    relevant_nodes, nop_nodes = get_relevant_nop_nodes(
        supergraph, pre_dispatcher_node, prologue_node, ret_nodes)
    print('*******************relevant blocks************************')
    print('prologue: %#x' % start)
    print('main_dispatcher: %#x' % main_dispatcher_node.addr)
    print('pre_dispatcher: %#x' % pre_dispatcher_node.addr)
    print('ret:', [hex(node.addr) for node in ret_nodes])
    relevant_block_addrs = [node.addr for node in relevant_nodes]
    print('relevant_blocks:', [hex(addr) for addr in relevant_block_addrs])

    print('*******************symbolic execution*********************')
    relevants = relevant_nodes
    relevants.append(prologue_node)
    relevants_without_retn = list(relevants)

    for node in ret_nodes:
        relevants.append(node)
    relevant_block_addrs.append(prologue_node.addr)
    relevant_block_addrs.extend([node.addr for node in ret_nodes])

    flow = defaultdict(list)
    patch_instrs = {}
    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant.addr)
        block = project.factory.block(relevant.addr, size=relevant.size)
        has_branches = False
        hook_addrs = set([])
        for ins in block.capstone.insns:
            if project.arch.name in ARCH_X86:
                if ins.insn.mnemonic.startswith('cmov'):
                    # only record the first one
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic.startswith('call'):
                    hook_addrs.add(ins.insn.address)
            elif project.arch.name in ARCH_ARM:
                if ins.insn.mnemonic != 'mov' and ins.insn.mnemonic.startswith('mov'):
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic in {'bl', 'blx'}:
                    hook_addrs.add(ins.insn.address)
            elif project.arch.name in ARCH_ARM64:
                if ins.insn.mnemonic.startswith('cset'):
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic in {'bl', 'blr'}:
                    hook_addrs.add(ins.insn.address)

        if has_branches:
            tmp_addr = symbolic_execution(project, relevant_block_addrs,
                                                     relevant.addr, hook_addrs, claripy.BVV(1, 1), True)
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr)
            tmp_addr = symbolic_execution(project, relevant_block_addrs,
                                                     relevant.addr, hook_addrs, claripy.BVV(0, 1), True)
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr)
        else:
            tmp_addr = symbolic_execution(project, relevant_block_addrs,
                                                     relevant.addr, hook_addrs)
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr)

    print('************************flow******************************')
    for k, v in flow.items():
        print('%#x: ' % k.addr, [hex(child) for child in v])

    print([hex(node.addr) for node in ret_nodes])

    print('************************patch*****************************')
    with open(filename, 'rb') as origin:
        # Attention: can't transform to str by calling decode() directly. so use bytearray instead.
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)

    recovery_file = filename
    recovery = open(recovery_file, 'wb')

    # patch irrelevant blocks
    for nop_node in nop_nodes:
        fill_nop(origin_data, nop_node.addr-base_addr,
                 nop_node.size, project.arch)

    # remove unnecessary control flows
    for parent, childs in flow.items():
        if len(childs) == 1:
            parent_block = project.factory.block(parent.addr, size=parent.size)
            last_instr = parent_block.capstone.insns[-1]
            file_offset = last_instr.address - base_addr
            # patch the last instruction to jmp
            if project.arch.name in ARCH_X86:
                fill_nop(origin_data, file_offset,
                         last_instr.size, project.arch)
                patch_value = ins_j_jmp_hex_x86(last_instr.address, childs[0], 'jmp')
            elif project.arch.name in ARCH_ARM:
                patch_value = ins_b_jmp_hex_arm(last_instr.address, childs[0], 'b')
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            elif project.arch.name in ARCH_ARM64:
                # FIXME: For aarch64/arm64, the last instruction of prologue seems useful in some cases, so patch the next instruction instead.
                if parent.addr == start:
                    file_offset += 4
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address+4, childs[0], 'b')
                else:
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address, childs[0], 'b')
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            patch_instruction(origin_data, file_offset, patch_value)
        else:
            instr = patch_instrs[parent]
            file_offset = instr.address - base_addr
            # patch instructions starting from `cmovx` to the end of block
            fill_nop(origin_data, file_offset, parent.addr +
                     parent.size - base_addr - file_offset, project.arch)
            if project.arch.name in ARCH_X86:
                # patch the cmovx instruction to jx instruction
                patch_value = ins_j_jmp_hex_x86(instr.address, childs[0], instr.mnemonic[len('cmov'):])
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 6
                # patch the next instruction to jmp instrcution
                patch_value = ins_j_jmp_hex_x86(instr.address+6, childs[1], 'jmp')
                patch_instruction(origin_data, file_offset, patch_value)
            elif project.arch.name in ARCH_ARM:
                # patch the movx instruction to bx instruction
                bx_cond = 'b' + instr.mnemonic[len('mov'):]
                patch_value = ins_b_jmp_hex_arm(instr.address, childs[0], bx_cond)
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 4
                # patch the next instruction to b instrcution
                patch_value = ins_b_jmp_hex_arm(instr.address+4, childs[1], 'b')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)
            elif project.arch.name in ARCH_ARM64:
                # patch the cset.xx instruction to bx instruction
                bx_cond = instr.op_str.split(',')[-1].strip()
                patch_value = ins_b_jmp_hex_arm64(instr.address, childs[0], bx_cond)
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 4
                # patch the next instruction to b instruction
                patch_value = ins_b_jmp_hex_arm64(instr.address+4, childs[1], 'b')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % recovery_file)


if __name__ == '__main__':
    filename = "ctf"
    project = angr.Project(filename, load_options={'auto_load_libs': False})
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    addrs = []
    for addr in addrs:
        target_function = cfg.functions.get(addr)
        main(target_function)
        exit(0)
