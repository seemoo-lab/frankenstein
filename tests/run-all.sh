#!/bin/sh

# Copy all tracked files to temp directory
root=$(git rev-parse --show-toplevel)
tmpdir=$(mktemp -d -t frankenstein-XXX)
echo Using tempdir $tmpdir
for fname in $(git ls-files); do
    [[ -d $(dirname "$tmpdir/$fname") ]] || mkdir -p $(dirname "$tmpdir/$fname")
    cp "$root/$fname" "$tmpdir/$fname"
done
cd "$tmpdir"

set -e

# python tests/project.py CYW20735B1 execute.exe heap.exe
# python tests/hci.py CYW20735B1
# 
# python tests/project.py CYW20819A1 execute.exe
# #python tests/hci.py CYW20819A1
# 
# python tests/project.py BCM4375BBCM4375B1
# 
# echo "" | python core/uc.py projects/CYW20735B1/gen/execute.exe

make -C projects/CYW20735B1
python cli.py -p projects/test --create
python cli.py -p projects/test -e projects/CYW20735B1/gen/execute.exe
