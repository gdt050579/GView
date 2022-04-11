import subprocess

class Opcode:
    def __init__(self, id, name, *args) -> None:
        self.id = id
        self.name = name
        self._rel = False
        self.args = args

    def rel(self):
        self._rel = not self._rel
        return self

    def is_relative(self):
        return self._rel

class Type:
    def __init__(self, t, is_wide=False):
        self.t = t

    def get_name(self):
        return self.t

    def is_unsigned(self):
        return self.t.startswith("u")
        

UINT8W = Type("uint8", True)
UINT8  = Type("uint8")
UINT16 = Type("uint16")
UINT32 = Type("uint32")
INT8   = Type("int8")
INT16  = Type("int16")
INT32  = Type("int32")

OPCODES = [
    # Constants
    Opcode(0, "nop"),

    Opcode(1, "aconst_null"),
    Opcode(2, "iconst_m1"),
    Opcode(3, "iconst_0"),
    Opcode(4, "iconst_1"),
    Opcode(5, "iconst_2"),
    Opcode(6, "iconst_3"),
    Opcode(7, "iconst_4"),
    Opcode(8, "iconst_5"),
    
    Opcode(9, "lconst_0"),
    Opcode(10, "lconst_1"),

    Opcode(11, "fconst_0"),
    Opcode(12, "fconst_1"),
    Opcode(13, "fconst_2"),

    Opcode(14, "dconst_0"),
    Opcode(15, "dconst_1"),

    Opcode(16, "bipush", INT8),
    Opcode(17, "sipush", INT16),

    Opcode(18, "ldc", UINT8),
    Opcode(19, "ldc_w", UINT16),
    Opcode(20, "ldc2_w", UINT16),

    # Loads
    Opcode(21, "iload", UINT8),
    Opcode(22, "lload", UINT8),
    Opcode(23, "fload", UINT8),
    Opcode(24, "dload", UINT8),
    Opcode(25, "aload", UINT8),

    Opcode(26, "iload_0"),
    Opcode(27, "iload_1"),
    Opcode(28, "iload_2"),
    Opcode(29, "iload_3"),

    Opcode(30, "lload_0"),
    Opcode(31, "lload_1"),
    Opcode(32, "lload_2"),
    Opcode(33, "lload_3"),

    Opcode(34, "fload_0"),
    Opcode(35, "fload_1"),
    Opcode(36, "fload_2"),
    Opcode(37, "fload_3"),

    Opcode(38, "dload_0"),
    Opcode(39, "dload_1"),
    Opcode(40, "dload_2"),
    Opcode(41, "dload_3"),

    Opcode(42, "aload_0"),
    Opcode(43, "aload_1"),
    Opcode(44, "aload_2"),
    Opcode(45, "aload_3"),

    Opcode(46, "iaload"),
    Opcode(47, "laload"),
    Opcode(48, "faload"),
    Opcode(49, "daload"),
    Opcode(50, "aaload"),
    Opcode(51, "baload"),
    Opcode(52, "caload"),
    Opcode(53, "saload"),

    # Stores
    Opcode(54, "istore", UINT8),
    Opcode(55, "lstore", UINT8),
    Opcode(56, "fstore", UINT8),
    Opcode(57, "dstore", UINT8),
    Opcode(58, "astore", UINT8),

    Opcode(59, "istore_0"),
    Opcode(60, "istore_1"),
    Opcode(61, "istore_2"),
    Opcode(62, "istore_3"),

    Opcode(63, "lstore_0"),
    Opcode(64, "lstore_1"),
    Opcode(65, "lstore_2"),
    Opcode(66, "lstore_3"),

    Opcode(67, "fstore_0"),
    Opcode(68, "fstore_1"),
    Opcode(69, "fstore_2"),
    Opcode(70, "fstore_3"),

    Opcode(71, "dstore_0"),
    Opcode(72, "dstore_1"),
    Opcode(73, "dstore_2"),
    Opcode(74, "dstore_3"),

    Opcode(75, "astore_0"),
    Opcode(76, "astore_1"),
    Opcode(77, "astore_2"),
    Opcode(78, "astore_3"),

    Opcode(79, "iastore"),
    Opcode(80, "lastore"),
    Opcode(81, "fastore"),
    Opcode(82, "dastore"),
    Opcode(83, "aastore"),
    Opcode(84, "bastore"),
    Opcode(85, "castore"),
    Opcode(86, "sastore"),

    # Stack
    Opcode(87, "pop"),
    Opcode(88, "pop2"),
    Opcode(89, "dup"),
    Opcode(90, "dup_x1"),
    Opcode(91, "dup_x2"),
    Opcode(92, "dup2"),
    Opcode(93, "dup2_x1"),
    Opcode(94, "dup2_x2"),
    Opcode(95, "swap"),

    # Math
    Opcode(96, "iadd"),
    Opcode(97, "ladd"),
    Opcode(98, "fadd"),
    Opcode(99, "dadd"),
    
    Opcode(100, "isub"),
    Opcode(101, "lsub"),
    Opcode(102, "fsub"),
    Opcode(103, "dsub"),
    
    Opcode(104, "imul"),
    Opcode(105, "lmul"),
    Opcode(106, "fmul"),
    Opcode(107, "dmul"),

    Opcode(108, "idiv"),
    Opcode(109, "ldiv"),
    Opcode(110, "fdiv"),
    Opcode(111, "ddiv"),

    Opcode(112, "irem"),
    Opcode(113, "lrem"),
    Opcode(114, "frem"),
    Opcode(115, "drem"),
    
    Opcode(116, "ineg"),
    Opcode(117, "lneg"),
    Opcode(118, "fneg"),
    Opcode(119, "dneg"),

    Opcode(120, "ishl"),
    Opcode(121, "lshl"),
    Opcode(122, "ishr"),
    Opcode(123, "lshr"),
    Opcode(124, "iushr"),
    Opcode(125, "lushr"),

    Opcode(126, "iand"),
    Opcode(127, "land"),
    Opcode(128, "ior"),
    Opcode(129, "lor"),
    Opcode(130, "ixor"),
    Opcode(131, "lxor"),

    Opcode(132, "iinc", UINT8, INT8),

    # Conversions

    # Comparisons
    Opcode(148, "lcmp"),
    Opcode(149, "fcmpl"),
    Opcode(150, "fcmpg"),
    Opcode(151, "dcmpl"),
    Opcode(152, "dcmpg"),

    Opcode(153, "ifeq", UINT16),
    Opcode(154, "ifne", UINT16),
    Opcode(155, "iflt", UINT16),
    Opcode(156, "ifge", UINT16),
    Opcode(157, "ifgt", UINT16),
    Opcode(158, "ifle", UINT16),

    Opcode(159, "if_icmpeq", INT16).rel(),
    Opcode(160, "if_icmpne", INT16).rel(),
    Opcode(161, "if_icmplt", INT16).rel(),
    Opcode(162, "if_icmpge", INT16).rel(),
    Opcode(163, "if_icmpgt", INT16).rel(),
    Opcode(164, "if_icmple", INT16).rel(),
    Opcode(165, "if_acmpeq", INT16).rel(),
    Opcode(166, "if_acmpne", INT16).rel(),

    # Control

    Opcode(167, "goto", INT16).rel(),
    Opcode(168, "jsr", INT16),
    Opcode(169, "ret", UINT8),

    Opcode(172, "ireturn"),
    Opcode(173, "lreturn"),
    Opcode(174, "freturn"),
    Opcode(175, "dreturn"),
    Opcode(176, "areturn"),
    Opcode(177, "return"),

    # References
    Opcode(178, "getstatic", UINT16),

    Opcode(182, "invokevirtual", UINT16),
    Opcode(183, "invokespecial", UINT16),
    Opcode(184, "invokestatic", UINT16),
    Opcode(185, "invokeinterface", UINT16, UINT8, UINT8),
    Opcode(186, "invokedynamic", UINT16, UINT8, UINT8, UINT8),

    Opcode(187, "ne", UINT16),
    Opcode(188, "newarray", UINT8),
    Opcode(189, "anewarray", UINT16),
    Opcode(190, "arraylength"),

    # Extended

    # Reserved
]

def get_type(type):
    match type:
        case UINT8:
            return "uint8"

output = '''
#include <iostream>
#include "global.hpp"

namespace GView::Java{
bool print_opcodes(BufferView buffer) {
    BufferReader reader(buffer.GetData(), buffer.GetLength());
    while (!reader.done()) {
        auto offset = reader.offset();

        uint8 opcode;
        READB(opcode);

        switch (opcode) {
'''

for op in OPCODES:
    output += f"case {op.id}: {{"
    cout = f'''std::cout << offset << ". " << "{op.name}"'''
    for i in range(0, len(op.args)):
        arg = op.args[i]
        output += f'''{arg.get_name()} arg_{i};
        READB(arg_{i});
        '''
        if op.is_relative():
            output += f"arg_{i} += ({arg.get_name()}) offset;"
        unsigned = "unsigned" if arg.is_unsigned() else "signed"
        cout += f"<<' ' << ({unsigned} long long) arg_{i}"
    output += cout + "<<'\\n';break;}"


output += "default: unimplemented;return false;}}"
output += '''return true;}}'''

file_name = "raw_opcodes.cpp"
with open(file_name, "w") as f:
    f.write(output.strip())

subprocess.run(["clang-format", "-i", "raw_opcodes.cpp"])