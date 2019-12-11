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
        for i in md.disasm(c, 0x0000):  # no offset
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
    while True:
        que = input("ROP>> ")
        print("")
        l1 = que.split(";")
        l2 = [ s.strip() for s in l1 ]
        l3 = list(filter(lambda x:x!='', l2))
        if l3:
            looker(d,l3)
            print("")

#----------------------------------------

# find all occurrences of last item
# then start from each point and search backwards
def looker(dis,ins):
    adrs = []
    gads = []
    nins = len(ins)-1  # subtract 1 snce basing search from this position
    for i in range(len(dis)):
        if dis[i][1] == ins[-1]:
            adrs.append(i)
    if adrs:
        for a in adrs:
            if nins < 1:
                gads.append(dis[a])
            else:
                beg = a-nins
                end = a+1
                part = dis[beg:end]
                is_gad = True
                for p in range(len(part)):
                    if part[p][1] != ins[p]:
                        is_gad = False
                        break
                if is_gad:
                    gads.append(part)
    if gads:
        for gg in gads:
            gad = str()
            for g in gg:
                if isinstance(g,list):
                    tmp = g[0]+'\t'+g[1]+' '+g[2]+'\n'
                    gad += tmp
                else:
                    tmp = gg[0]+'\t'+gg[1]+' '+gg[2]+'\n'
                    gad += tmp
                    break
            print(gad)

    # quit()

#========================================
#========================================

if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) == 0:
        print("Error: missing arguments")
        print("Usage: ./IG.py file")
        exit(1)
    main(args)
