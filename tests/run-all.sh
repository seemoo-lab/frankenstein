#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR
cd ..

set -e

python3 tests/project.py CYW20735B1 execute.exe heap.exe
python3 tests/hci.py CYW20735B1

python3 tests/project.py CYW20819A1 execute.exe
#python3 tests/hci.py CYW20819A1

python3 tests/project.py BCM4375BBCM4375B1

echo "" | python3 core/uc.py projects/CYW20735B1/gen/execute.exe
