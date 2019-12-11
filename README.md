# Inspector_Gadget

ROP Gadget finder

When using ROP, an attacker uses their control over the stack right before the return from a function to direct code execution to some other location in the program.
This looks for specific combinations of instructions called gadgets which will do this.

written in python3 using capstone disassembly framework.

## Usage

Mode: use interactively to find gadgets

`./IG.py a.out`

includes some 32 bit rop examples from ctf games
