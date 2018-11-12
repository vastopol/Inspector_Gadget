#!/usr/bin/python3

# right now just x86 32bit

# imports
import sys
from capstone import *

#----------------------------------------

def main(args):
    outf1 = open("dis_out.txt","a")
    outf2 = open("dis_rop.txt","a")
    f_names = []
    dis_files = []

    for a in args:
        print("Disassemble %s" %a)
        new_dis = disassemble(a,outf1)
        f_names.append(a)
        dis_files.append(new_dis)
    outf1.close()

    fidx = 0
    for d in dis_files:
        print("ROP Find %s" %f_names[fidx])
        rop_find(f_names[fidx],d,outf2)
        fidx += 1
    outf2.close()

#----------------------------------------

# output the asm to a file
# return a 2d list of instructions [ [addr,mnem,op_str], ... ]
def disassemble(a,outf1):
    instructions = []
    b = open(a, 'rb')
    c = b.read()
    outf1.write("Disassembly for %s\n\n" %(a))
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(c, 0x1000):
            i1 = hex(i.address)
            i2 = str(i.mnemonic)
            i3 = (i.op_str)
            instructions.append([i1,i2,i3])
            outf1.write("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            outf1.write("\n")
        outf1.write("\n")
    except CsError as e:
        print("ERROR: %s" %e)
    return instructions

#----------------------------------------

# take 2d list and look for gadgets
def rop_find(f,d,outf2):
    outf2.write("ROP Gadgets for %s\n\n" %(f))
    outf2.write("Pop\n\n")
    find_pop_pop(d,outf2)
    find_pop_ret(d,outf2)
    outf2.write("Load/Store\n\n")
    find_mov_ret(d,outf2)
    find_xchg_ret(d,outf2)
    find_lea_ret(d,outf2)
    outf2.write("Arithmetic\n\n")
    find_xor_ret(d,outf2)
    find_add_ret(d,outf2)
    find_sub_ret(d,outf2)
#----------------------------------------

# pop pop
def find_pop_pop(d,outf2):
    outf2.write("pop ; pop\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "pop" and curr[1] == "pop":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

# pop ret
def find_pop_ret(d,outf2):
    outf2.write("pop ; ret\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "pop" and curr[1] == "ret":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

# should find load/store types of gadgets
def find_mov_ret(d,outf2):
    outf2.write("mov ; ret\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "mov" and curr[1] == "ret":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

# xchg ret
def find_xchg_ret(d,outf2):
    outf2.write("xchg ; ret\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "xchg" and curr[1] == "ret":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

# xchg ret
def find_lea_ret(d,outf2):
    outf2.write("lea ; ret\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "lea" and curr[1] == "ret":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

# arithmetic with xor
def find_xor_ret(d,outf2):
    outf2.write("xor ; ret\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "xor" and curr[1] == "ret":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

# arithmetic with add
def find_add_ret(d,outf2):
    outf2.write("add ; ret\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "add" and curr[1] == "ret":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

# arithmetic with sub
def find_sub_ret(d,outf2):
    outf2.write("sub ; ret\n\n")
    prev = d[0]
    pdex = 0
    for i in range(1,len(d)):
        curr = d[i]
        if prev[1] == "sub" and curr[1] == "ret":
            outf2.write("\t" + str(prev))
            outf2.write("\n")
            outf2.write("\t" + str(curr))
            outf2.write("\n\n")
        prev = d[i]
        pdex += 1

#----------------------------------------

#========================================
#========================================

if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) == 0:
        print("Error: missing arguments")
        print("Usage: ./IG.py files")
        exit(1)
    main(args)
