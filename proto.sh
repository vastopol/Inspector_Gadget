#!/bin/bash

OUTF=tmpfile.txt

objdump -M intel -d $1 > $OUTF

echo "pop"
grep "pop" $OUTF

echo "ret"
grep "ret" $OUTF

echo

echo "pop; ret"
awk '/pop/,/ret/' $OUTF

