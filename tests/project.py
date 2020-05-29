import os
import sys
from binascii import hexlify, unhexlify
from subprocess import Popen, PIPE, STDOUT

sys.path.append("..")
sys.path.append(".")
from core.project import Project

def run(cmd, stdin="", returncode=0):
    print("Running: %s" % cmd)
    p = Popen(["bash", "-c", cmd], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stderr,stdout = p.communicate(stdin)
    if p.returncode != returncode:
        print(stdout.decode("utf-8"))
        print(stderr.decode("utf-8"))
        print("Command returned invalid return code.")
        print("Expected %d got %d" % (returncode, p.returncode))
        sys.exit(-1)

def test_project_basic(project_name):
    run("make -C projects/%s" % project_name)

    print("Loading project %s" % project_name)
    p = Project("projects/%s" % project_name)

    print("Set default group active")
    assert p.group_deactivate_all()
    assert p.group_set_active("default")

    print("Save")
    assert p.save()

    print("Generating build scripts")
    assert p.create_build_scripts()

    run("make -C projects/%s" % project_name)

if len(sys.argv) < 2:
    print("usage %s project_name [test_binary1 [test_binary2]]" % sys.argv[0])
    sys.exit(1)


test_project_basic(sys.argv[1])
for binary in sys.argv[2:]:
    run("qemu-arm projects/"+sys.argv[1]+"/gen/"+binary)
