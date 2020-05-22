from core.project import Project

from optparse import OptionParser


def main(options, args):
    print(options, args)

    p = Project(options.projectName, allow_create=options.projectCreate)

    if options.deleteGroup:
        p.group_delete(options.deleteGroup)

    if options.loadELF:
        p.load_elf(options.loadELF, load_segments=options.loadSegments, load_symbols=options.loadSymbols)

    p.show()

parser = OptionParser()
parser.add_option("-p", "--project", dest="projectName",
                  help="Path to project", metavar="DIR")

parser.add_option("-c", "--create", dest="projectCreate", action="store_true",
                  help="Create new project", default=False)

# Load
parser.add_option("-e", "--load-elf", dest="loadELF",
                  help="Path to project", metavar="FILE")

parser.add_option("", "--no-symbols", dest="loadSymbols", action="store_false",
                  help="Create new project", default=True)
parser.add_option("", "--no-segments", dest="loadSegments", action="store_false",
                  help="Create new project", default=True)

# Segment group management
parser.add_option("", "--group-delete", dest="deleteGroup", 
                  help="Delete group", default=False)

(options, args) = parser.parse_args()

if not options.projectName:
    parser.error('projectName not given')

main(options, args)
