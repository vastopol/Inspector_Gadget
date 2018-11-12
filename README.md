# Inspector_Gadget

ROP Gadget finder

When using ROP, an attacker uses their control over the stack right before the return from a function to direct code execution to some other location in the program.
This looks for specific combinations of instructions called gadgets which will do this.

written in python3 using capstone disassembly framework.

ROP Resources:

https://en.wikipedia.org/wiki/Return-oriented_programming

https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf

https://media.blackhat.com/us-13/US-13-Quynh-OptiROP-Hunting-for-ROP-Gadgets-in-Style-Slides.pdf

https://amslaurea.unibo.it/4682/1/Prati_Marco_tesi.pdf

https://nebelwelt.net/publications/files/16STM.pdf

