#!/usr/bin/python3

# right now just x86 32bit

# imports
import sys
from capstone import *

#----------------------------------------

def main(args):
    print("ROP FINDER")
    outf = open("dis_output.txt","a")
    for a in args:
        print("Disassemble %s" %a)
        disassemble(a,outf)

def disassemble(a,outf):
    b = open(a, 'rb')
    c = b.read()
    # print(str(c))
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(c, 0x1000):
    	    # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            outf.write("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            outf.write("\n")
    except CsError as e:
        print("ERROR: %s" %e)

#----------------------------------------

if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) == 0:
        print("Error: missing arguments")
        print("Usage: ./IG.py files")
        exit(1)
    main(args)
