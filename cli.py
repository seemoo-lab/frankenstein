import os, sys
from core.project import Project
from optparse import OptionParser, OptionGroup


def project_main(options, args):
    p = Project(options.projectName, allow_create=options.projectCreate)

    if options.deleteGroup:
        p.group_delete(options.deleteGroup)

    if options.loadELF:
        p.load_elf(options.loadELF, load_segments=options.loadSegments, load_symbols=options.loadSymbols)

    if options.symbolize:
        for addr in args[1:]:
            addr = int(addr, 0)
            name = p.symbolize(addr)
            print("0x%x = %s" % (addr, name))

    if options.show:
        p.show()

def project_optparse(argv):
    parser = OptionParser()
    parser.add_option("-p", "--project", dest="projectName",
                      help="Path to project", metavar="DIR", default=".")

    parser.add_option("-c", "--create", dest="projectCreate", action="store_true",
                      help="Create new project", default=False)

    parser.add_option("-s", "--show", dest="show", action="store_true",
                      help="Show project details", default=False)

    parser.add_option("-S", "--symbolize", dest="symbolize", action="store_true",
                      help="Lookup symbol by address", default=False)

    # Load
    group = OptionGroup(parser, "Loading files")
    group.add_option("-e", "--load-elf", dest="loadELF",
                      help="Path to project", metavar="FILE")

    group.add_option("", "--no-symbols", dest="loadSymbols", action="store_false",
                      help="Create new project", default=True)
    group.add_option("", "--no-segments", dest="loadSegments", action="store_false",
                      help="Create new project", default=True)
    parser.add_option_group(group)

    # Segment group management
    group = OptionGroup(parser, "Group management")
    group.add_option("", "--group-delete", dest="deleteGroup", 
                      help="Delete group", default=False)
    parser.add_option_group(group)

    (options, args) = parser.parse_args(argv)

    if len(argv) == 1:
        parser.print_help()
        parser.error('No action taken')

    cfg = os.path.join(options.projectName, "project.json")
    if not os.path.isfile(cfg) and not options.projectCreate:
        parser.print_help()
        parser.error('projectName not given')

    project_main(options, args)

def usage():
    print("usage %s [module]" % sys.argv[0])
    print("Modules:")
    print("\tproject            Manage projects")
    print("\tdjago              Django console")
    sys.exit(-1)



if len(sys.argv) == 1:
    usage()

module = sys.argv[1]
if module == "project":
    project_optparse(sys.argv[1:])

elif module == "django":
    from django.core.management import execute_from_command_line
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "frankensteinWebUI.settings")
    execute_from_command_line(sys.argv[1:])

else:
    usage()

