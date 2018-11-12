#!/usr/bin/python3

# right now just x86 32bit

# imports
import sys
from capstone import *

#----------------------------------------

def main(args):
    new_dis = disassemble(args[0])
    rop_find(new_dis)

#----------------------------------------

# output the asm to a file
# return a 2d list of instructions [ [addr,mnem,op_str], ... ]
def disassemble(a):
    print("Disassemble %s" %(a))
    instructions = []
    b = open(a, 'rb')
    c = b.read()
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(c, 0x1000):
            i1 = hex(i.address)
            i2 = str(i.mnemonic)
            i3 = (i.op_str)
            instructions.append([i1,i2,i3])
    except CsError as e:
        print("ERROR: %s" %e)
    return instructions

#----------------------------------------

# take 2d list and ask user for pattern to look for gadgets
def rop_find(d):
    print("ROP Find\n")
    while True:
        que = input("ROP>> ")
        print("")
        l1 = que.split(";")
        l2 = [ s.strip() for s in l1 ]
        looker(d,l2)
        print("")

#----------------------------------------

# not 100% working really broken...
# does not properly back track and start from +1 where was previously
def looker(d,l):
    ops_len = len(l) # num of ops to look for
    ops_cnt = 0
    ops_vek = []
    holder = 0

    i = 0
    while i < len(d):
        curr = d[i]
        if curr[1] == l[ops_cnt]:
            holder = i
            while curr[1] == l[ops_cnt]:
                ops_vek.append(curr)
                ops_cnt += 1
                curr = d[i+1]
                if ops_cnt == ops_len:
                    prev = ops_vek[0]
                    for j in range(1,len(ops_vek)):
                        if ops_vek[j][0] == prev[0]:
                            ops_vek = []
                            ops_cnt = 0
                            i = holder+1
                            break
                        break
                        prev = ops_vek[j]
                    if len(ops_vek) > 0:
                        print(ops_vek)
                        ops_vek = []
                        ops_cnt = 0
                        i = holder+1
                        break
            continue
        else:
            ops_cnt = 0
            ops_vek = []
        i += 1

#========================================
#========================================

if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) == 0:
        print("Error: missing arguments")
        print("Usage: ./IG.py file")
        exit(1)
    main(args)
