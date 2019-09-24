## Introduction

This tool contains a web-based UI to configure the build.
This includes management of symbols and memory dumps.
The Makefile and linker scripts are generated automatically by the build system.
The build system can be launched by the following command and navigating the browser to [http://127.0.0.1:8000/](http://127.0.0.1:8000)

```
python2 manage.py runserver
```

Currently, only the CYW20735 eval board is supported.
Each firmware version is located in a different project stored in "projects".
This contains the file "project.json", which holds the symbol names and the memory layout including memory dumps.
The available symbols can be used to generate patches in C as well as firmware emulation.
To build all patches and emulators run:

```
make -C projects/CYW20735-B1
```

The most important patch is "patch/xmit_state.h" that is used to generate executable firmware states.
It is used in a custom internal blue extension "internalBlueMod.py".
In this extension, we can run the following command to generate an executable state.

```
xmitstate target_function
```

After rebuilding the project using "make -C projects/CYW20735-B1", the firmware state can be emulated, until the 'Idle' thread is entered by running:

```
qemu-arm projects/CYW20735-B1/gen/execute.exe
```


## Project structure
[Link](projects/)
