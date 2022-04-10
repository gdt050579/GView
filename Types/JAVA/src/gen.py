from enum import Enum
import subprocess

class Opcode:
    def __init__(self, id, name, *args) -> None:
        self.id = id
        self.name = name
        self.args = args

class Type(Enum):
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"

    def __init__(self, t):
        self.t = t

    def get_name(self):
        return self.t
        

UINT8 = Type.UINT8
UINT16 = Type.UINT16
UINT32 = Type.UINT32

OPCODES = [
    Opcode(18, "ldc", UINT8),
    Opcode(19, "ldc_w", UINT16),
    Opcode(20, "ldc2_w", UINT16),

    Opcode(25, "aload", UINT8),
    Opcode(42, "aload_0"),
    Opcode(43, "aload_1"),
    Opcode(44, "aload_2"),
    Opcode(45, "aload_3"),

    Opcode(172, "ireturn"),
    Opcode(173, "lreturn"),
    Opcode(174, "freturn"),
    Opcode(175, "dreturn"),
    Opcode(176, "areturn"),
    Opcode(177, "return"),

    Opcode(178, "getstatic", UINT16),

    Opcode(182, "invokevirtual", UINT16),
    Opcode(183, "invokespecial", UINT16),
    Opcode(184, "invokestatic", UINT16),
    Opcode(185, "invokeinterface", UINT16, UINT8, UINT8),
    Opcode(186, "invokedynamic", UINT16, UINT8, UINT8, UINT8),
]

def get_type(type):
    match type:
        case UINT8:
            return "uint8"

output = '''
#include "global.hpp"

namespace GView::Java{
bool print_opcodes(BufferView buffer) {
    BufferReader reader(buffer.GetData(), buffer.GetLength());
    while (!reader.done()) {
        uint8 opcode;
        READB(opcode);

        switch (opcode) {
'''

for op in OPCODES:
    output += f"case {op.id}: {{"
    for i in range(0, len(op.args)):
        arg = op.args[i]
        output += f'''{arg.get_name()} arg_{i};
        READB(arg_{i});
        '''
    output += f'''printf("{op.name}\\n");'''
    output += "break;}"


output += "default: unimplemented;return false;}}"
output += '''return true;}}'''

file_name = "raw_opcodes.cpp"
with open(file_name, "w") as f:
    f.write(output.strip())

subprocess.run(["clang-format", "-i", "raw_opcodes.cpp"])