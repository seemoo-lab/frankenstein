#!/bin/sh

# Copy all tracked files to temp directory
root=$(git rev-parse --show-toplevel)
tmpdir=$(mktemp -d -t frankenstein-XXXX)
echo Using tempdir $tmpdir
for fname in $(git ls-files); do
    [[ -d $(dirname "$tmpdir/$fname") ]] || mkdir -p $(dirname "$tmpdir/$fname")
    cp "$root/$fname" "$tmpdir/$fname"
done
cd "$tmpdir"

set -e

bash tests/hook.sh arm-none-eabi-gcc -D TEST_THUMB
bash tests/hook.sh arm-none-eabi-gcc

python3 tests/project.py CYW20735B1 execute.exe heap.exe
python3 tests/hci.py CYW20735B1
 
python3 tests/project.py CYW20819A1 execute.exe
#python3 tests/hci.py CYW20819A1
 
python3 tests/project.py BCM4375B1
 
echo "" | python3 core/uc.py projects/CYW20735B1/gen/execute.exe
