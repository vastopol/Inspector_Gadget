# Inspector_Gadget

ROP Gadget finder

When using ROP, an attacker uses their control over the stack right before the return from a function to direct code execution to some other location in the program.
This looks for specific combinations of instructions called gadgets which will do this.

written in python3 using capstone disassembly framework.

## usage
Static mode: will look for predefined patterns, output 2 files
```
gcc -m32 file.c
./IG.py a.out
```

Dynamic Mode: use interactively to find gadgets
```
gcc -m32 file.c
./IG2.py a.out
```
