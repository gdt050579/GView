import sys
import os

if len(sys.argv) < 2:
    print("Failed to obtain GView.hpp location")
    exit(1)

header_location = sys.argv[1]
if not os.path.exists(header_location):
    print("Path {} does not exists!".format(header_location))
    exit(1)

version = None
with open(header_location, 'r') as f:
    for line in f:
        if line.startswith('#define GVIEW_VERSION '):
            version = line.split('#define GVIEW_VERSION ')[1].strip(' \r\n\t\"')
            break

if version is None:
    print("Failed to find GVIEW_VERSION")
    exit(1)

print(version)
exit(0)
