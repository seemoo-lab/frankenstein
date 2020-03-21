import os
import sys
from subprocess import Popen, PIPE, STDOUT
from binascii import hexlify, unhexlify


def hci_read_event(fd):
    event = fd.read(1)
    if event[0] == 0x04: #HCI Event
        event += fd.read(2)
        event += fd.read(event[2])

    else:
        raise

    return event

def hci_test(cmd):
    sys.stderr.write("Running: %s\n" % cmd)
    p = Popen(["bash", "-c", cmd], stdin=PIPE, stdout=PIPE)

    sys.stderr.write("Testing reset ")
    p.stdin.write(unhexlify("01030c00"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == b"040e0401030c00"
    sys.stderr.write("\033[;32mOk\033[;0m\n")

    sys.stderr.write("Write EIR ")
    p.stdin.write(unhexlify("01520cf100" + "42"*0xf0))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == b"040e0401520c00"
    sys.stderr.write("\033[;32mOk\033[;0m\n")

    sys.stderr.write("Read EIR ")
    p.stdin.write(unhexlify("01510c00"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == b"040ef501510c0000"+b"42"*0xf0
    sys.stderr.write("\033[;32mOk\033[;0m\n")

    sys.stderr.write("Enable lescan ")
    p.stdin.write(unhexlify("010c20020101"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == b"040e04010c2000"
    sys.stderr.write("\033[;32mOk\033[;0m\n")

    sys.stderr.write("Waiting for LE scan result ")
    assert hexlify(hci_read_event(p.stdout))[:4] == b"043e" #LE Scan Result
    sys.stderr.write("\033[;32mOk\033[;0m\n")

    sys.stderr.write("Disable lescan ")
    p.stdin.write(unhexlify("010c20020001"))
    p.stdin.flush()
    while hexlify(hci_read_event(p.stdout)) != b"040e04010c2000":
        pass
    sys.stderr.write("\033[;32mOk\033[;0m\n")

    sys.stderr.write("Start Inquiry ")
    p.stdin.write(unhexlify("01010405338b9e0000"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == b"040f0400010104"
    sys.stderr.write("\033[;32mOk\033[;0m\n")

    sys.stderr.write("Waiting for crash (CVE-2019-11516)\n")
    while True:
        try:
            print("Got Result:", hexlify(hci_read_event(p.stdout)))
        except:
            break

hci_test("qemu-arm projects/"+sys.argv[1]+"/gen/hci_test.exe 2>/dev/null")
