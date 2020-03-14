#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR
cd ..

set -e

python2 tests/project.py CYW20735B1 execute.exe heap.exe
python2 tests/hci.py CYW20735B1

python2 tests/project.py CYW20819A1 execute.exe
#python2 tests/hci.py CYW20819A1

python2 tests/project.py BCM4375BBCM4375B1
