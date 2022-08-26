import os

VCPKG_ROOT = os.environ.get('VCPKG_ROOT', None)
if VCPKG_ROOT is None:
        raise Exception("VCKPG_ROOT not set!")

ncurses_port_filepath = '{}/ports/ncurses/portfile.cmake'.format(VCPKG_ROOT)
print(ncurses_port_filepath)

with open(ncurses_port_filepath, 'r') as f:
        lines = f.readlines()
        print(lines)

options_line_index = lines.index('set(OPTIONS\r\n')
print('Options Line Index #{}'.format(options_line_index))

lines.insert(options_line_index + 1, '    --enable-widec\r\n')
print(lines)

with open(ncurses_port_filepath, 'w') as f:
        f.write(''.join(lines))
    
