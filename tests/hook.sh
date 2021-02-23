set -e -x

GCC=$@
PROJECT=tests/hook_test

pwd
$GCC tests/hook_test.c -I include -I tests -static -nostdlib -D FRANKENSTEIN_EMULATION -I /usr/include -o tests/hook_test.exe

if [ -d "$PROJECT" ]; then
    rm -rf "$PROJECT"
fi

python3 cli.py project -p $PROJECT -c -e tests/hook_test.exe

cp tests/hook_emu.c $PROJECT/emulation
make -C $PROJECT
qemu-arm $PROJECT/gen/hook_emu.exe

rm -rf $PROJECT
