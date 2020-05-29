set -e

GCC=$@
PROJECT=tests/hook_test

$GCC tests/hook_test.c -I include -static -nostdlib -D FRANKENSTEIN_EMULATION -I /usr/include -o tests/hook_test.exe

python3 cli.py -p $PROJECT -c -e tests/hook_test.exe

cp tests/hook_emu.c $PROJECT/emulation
make -C $PROJECT
qemu-arm $PROJECT/gen/hook_emu.exe

rm -rf $PROJECT
