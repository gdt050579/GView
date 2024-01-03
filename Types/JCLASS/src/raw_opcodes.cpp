#include "global.hpp"

namespace GView::Java
{
static const char* NAMES[256] = {
    "nop",           "aconst_null", "iconst_m1",     "iconst_0",      "iconst_1",     "iconst_2",
    "iconst_3",      "iconst_4",    "iconst_5",      "lconst_0",      "lconst_1",     "fconst_0",
    "fconst_1",      "fconst_2",    "dconst_0",      "dconst_1",      "bipush",       "sipush",
    "ldc",           "ldc_w",       "ldc2_w",        "iload",         "lload",        "fload",
    "dload",         "aload",       "iload_0",       "iload_1",       "iload_2",      "iload_3",
    "lload_0",       "lload_1",     "lload_2",       "lload_3",       "fload_0",      "fload_1",
    "fload_2",       "fload_3",     "dload_0",       "dload_1",       "dload_2",      "dload_3",
    "aload_0",       "aload_1",     "aload_2",       "aload_3",       "iaload",       "laload",
    "faload",        "daload",      "aaload",        "baload",        "caload",       "saload",
    "istore",        "lstore",      "fstore",        "dstore",        "astore",       "istore_0",
    "istore_1",      "istore_2",    "istore_3",      "lstore_0",      "lstore_1",     "lstore_2",
    "lstore_3",      "fstore_0",    "fstore_1",      "fstore_2",      "fstore_3",     "dstore_0",
    "dstore_1",      "dstore_2",    "dstore_3",      "astore_0",      "astore_1",     "astore_2",
    "astore_3",      "iastore",     "lastore",       "fastore",       "dastore",      "aastore",
    "bastore",       "castore",     "sastore",       "pop",           "pop2",         "dup",
    "dup_x1",        "dup_x2",      "dup2",          "dup2_x1",       "dup2_x2",      "swap",
    "iadd",          "ladd",        "fadd",          "dadd",          "isub",         "lsub",
    "fsub",          "dsub",        "imul",          "lmul",          "fmul",         "dmul",
    "idiv",          "ldiv",        "fdiv",          "ddiv",          "irem",         "lrem",
    "frem",          "drem",        "ineg",          "lneg",          "fneg",         "dneg",
    "ishl",          "lshl",        "ishr",          "lshr",          "iushr",        "lushr",
    "iand",          "land",        "ior",           "lor",           "ixor",         "lxor",
    "iinc",          "i2l",         "i2f",           "i2d",           "l2i",          "l2f",
    "l2d",           "f2i",         "f2l",           "f2d",           "d2i",          "d2l",
    "d2f",           "i2b",         "i2c",           "i2s",           "lcmp",         "fcmpl",
    "fcmpg",         "dcmpl",       "dcmpg",         "ifeq",          "ifne",         "iflt",
    "ifge",          "ifgt",        "ifle",          "if_icmpeq",     "if_icmpne",    "if_icmplt",
    "if_icmpge",     "if_icmpgt",   "if_icmple",     "if_acmpeq",     "if_acmpne",    "goto",
    "jsr",           "ret",         "tableswitch",   "lookupswitch",  "ireturn",      "lreturn",
    "freturn",       "dreturn",     "areturn",       "return",        "getstatic",    "putstatic",
    "getfield",      "putfield",    "invokevirtual", "invokespecial", "invokestatic", "invokeinterface",
    "invokedynamic", "new",         "newarray",      "anewarray",     "arraylength",  "athrow",
    "checkcast",     "instanceof",  "monitorenter",  "monitorexit",   "wide",         "multianewarray",
    "ifnull",        "ifnonnull",   "goto_w",        "jsr_w",
};

const char* Opcode::get_name() const
{
    return NAMES[opcode];
}

bool get_opcode(BufferReader& reader, Opcode& out)
{
    out         = {};
    auto offset = reader.offset();

    READB(out.opcode);
    switch (out.opcode)
    {
    case 0:
    {
        // nop
        break;
    }
    case 1:
    {
        // aconst_null
        break;
    }
    case 2:
    {
        // iconst_m1
        break;
    }
    case 3:
    {
        // iconst_0
        break;
    }
    case 4:
    {
        // iconst_1
        break;
    }
    case 5:
    {
        // iconst_2
        break;
    }
    case 6:
    {
        // iconst_3
        break;
    }
    case 7:
    {
        // iconst_4
        break;
    }
    case 8:
    {
        // iconst_5
        break;
    }
    case 9:
    {
        // lconst_0
        break;
    }
    case 10:
    {
        // lconst_1
        break;
    }
    case 11:
    {
        // fconst_0
        break;
    }
    case 12:
    {
        // fconst_1
        break;
    }
    case 13:
    {
        // fconst_2
        break;
    }
    case 14:
    {
        // dconst_0
        break;
    }
    case 15:
    {
        // dconst_1
        break;
    }
    case 16:
    {
        // bipush

        int8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 17:
    {
        // sipush

        int16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 18:
    {
        // ldc

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 19:
    {
        // ldc_w

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 20:
    {
        // ldc2_w

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 21:
    {
        // iload

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 22:
    {
        // lload

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 23:
    {
        // fload

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 24:
    {
        // dload

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 25:
    {
        // aload

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 26:
    {
        // iload_0
        break;
    }
    case 27:
    {
        // iload_1
        break;
    }
    case 28:
    {
        // iload_2
        break;
    }
    case 29:
    {
        // iload_3
        break;
    }
    case 30:
    {
        // lload_0
        break;
    }
    case 31:
    {
        // lload_1
        break;
    }
    case 32:
    {
        // lload_2
        break;
    }
    case 33:
    {
        // lload_3
        break;
    }
    case 34:
    {
        // fload_0
        break;
    }
    case 35:
    {
        // fload_1
        break;
    }
    case 36:
    {
        // fload_2
        break;
    }
    case 37:
    {
        // fload_3
        break;
    }
    case 38:
    {
        // dload_0
        break;
    }
    case 39:
    {
        // dload_1
        break;
    }
    case 40:
    {
        // dload_2
        break;
    }
    case 41:
    {
        // dload_3
        break;
    }
    case 42:
    {
        // aload_0
        break;
    }
    case 43:
    {
        // aload_1
        break;
    }
    case 44:
    {
        // aload_2
        break;
    }
    case 45:
    {
        // aload_3
        break;
    }
    case 46:
    {
        // iaload
        break;
    }
    case 47:
    {
        // laload
        break;
    }
    case 48:
    {
        // faload
        break;
    }
    case 49:
    {
        // daload
        break;
    }
    case 50:
    {
        // aaload
        break;
    }
    case 51:
    {
        // baload
        break;
    }
    case 52:
    {
        // caload
        break;
    }
    case 53:
    {
        // saload
        break;
    }
    case 54:
    {
        // istore

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 55:
    {
        // lstore

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 56:
    {
        // fstore

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 57:
    {
        // dstore

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 58:
    {
        // astore

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 59:
    {
        // istore_0
        break;
    }
    case 60:
    {
        // istore_1
        break;
    }
    case 61:
    {
        // istore_2
        break;
    }
    case 62:
    {
        // istore_3
        break;
    }
    case 63:
    {
        // lstore_0
        break;
    }
    case 64:
    {
        // lstore_1
        break;
    }
    case 65:
    {
        // lstore_2
        break;
    }
    case 66:
    {
        // lstore_3
        break;
    }
    case 67:
    {
        // fstore_0
        break;
    }
    case 68:
    {
        // fstore_1
        break;
    }
    case 69:
    {
        // fstore_2
        break;
    }
    case 70:
    {
        // fstore_3
        break;
    }
    case 71:
    {
        // dstore_0
        break;
    }
    case 72:
    {
        // dstore_1
        break;
    }
    case 73:
    {
        // dstore_2
        break;
    }
    case 74:
    {
        // dstore_3
        break;
    }
    case 75:
    {
        // astore_0
        break;
    }
    case 76:
    {
        // astore_1
        break;
    }
    case 77:
    {
        // astore_2
        break;
    }
    case 78:
    {
        // astore_3
        break;
    }
    case 79:
    {
        // iastore
        break;
    }
    case 80:
    {
        // lastore
        break;
    }
    case 81:
    {
        // fastore
        break;
    }
    case 82:
    {
        // dastore
        break;
    }
    case 83:
    {
        // aastore
        break;
    }
    case 84:
    {
        // bastore
        break;
    }
    case 85:
    {
        // castore
        break;
    }
    case 86:
    {
        // sastore
        break;
    }
    case 87:
    {
        // pop
        break;
    }
    case 88:
    {
        // pop2
        break;
    }
    case 89:
    {
        // dup
        break;
    }
    case 90:
    {
        // dup_x1
        break;
    }
    case 91:
    {
        // dup_x2
        break;
    }
    case 92:
    {
        // dup2
        break;
    }
    case 93:
    {
        // dup2_x1
        break;
    }
    case 94:
    {
        // dup2_x2
        break;
    }
    case 95:
    {
        // swap
        break;
    }
    case 96:
    {
        // iadd
        break;
    }
    case 97:
    {
        // ladd
        break;
    }
    case 98:
    {
        // fadd
        break;
    }
    case 99:
    {
        // dadd
        break;
    }
    case 100:
    {
        // isub
        break;
    }
    case 101:
    {
        // lsub
        break;
    }
    case 102:
    {
        // fsub
        break;
    }
    case 103:
    {
        // dsub
        break;
    }
    case 104:
    {
        // imul
        break;
    }
    case 105:
    {
        // lmul
        break;
    }
    case 106:
    {
        // fmul
        break;
    }
    case 107:
    {
        // dmul
        break;
    }
    case 108:
    {
        // idiv
        break;
    }
    case 109:
    {
        // ldiv
        break;
    }
    case 110:
    {
        // fdiv
        break;
    }
    case 111:
    {
        // ddiv
        break;
    }
    case 112:
    {
        // irem
        break;
    }
    case 113:
    {
        // lrem
        break;
    }
    case 114:
    {
        // frem
        break;
    }
    case 115:
    {
        // drem
        break;
    }
    case 116:
    {
        // ineg
        break;
    }
    case 117:
    {
        // lneg
        break;
    }
    case 118:
    {
        // fneg
        break;
    }
    case 119:
    {
        // dneg
        break;
    }
    case 120:
    {
        // ishl
        break;
    }
    case 121:
    {
        // lshl
        break;
    }
    case 122:
    {
        // ishr
        break;
    }
    case 123:
    {
        // lshr
        break;
    }
    case 124:
    {
        // iushr
        break;
    }
    case 125:
    {
        // lushr
        break;
    }
    case 126:
    {
        // iand
        break;
    }
    case 127:
    {
        // land
        break;
    }
    case 128:
    {
        // ior
        break;
    }
    case 129:
    {
        // lor
        break;
    }
    case 130:
    {
        // ixor
        break;
    }
    case 131:
    {
        // lxor
        break;
    }
    case 132:
    {
        // iinc

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;

        int8 second;
        READB(second);
        out.args[1].value       = second;
        out.args[1].exists      = true;
        out.args[1].is_unsigned = false;
        break;
    }
    case 133:
    {
        // i2l
        break;
    }
    case 134:
    {
        // i2f
        break;
    }
    case 135:
    {
        // i2d
        break;
    }
    case 136:
    {
        // l2i
        break;
    }
    case 137:
    {
        // l2f
        break;
    }
    case 138:
    {
        // l2d
        break;
    }
    case 139:
    {
        // f2i
        break;
    }
    case 140:
    {
        // f2l
        break;
    }
    case 141:
    {
        // f2d
        break;
    }
    case 142:
    {
        // d2i
        break;
    }
    case 143:
    {
        // d2l
        break;
    }
    case 144:
    {
        // d2f
        break;
    }
    case 145:
    {
        // i2b
        break;
    }
    case 146:
    {
        // i2c
        break;
    }
    case 147:
    {
        // i2s
        break;
    }
    case 148:
    {
        // lcmp
        break;
    }
    case 149:
    {
        // fcmpl
        break;
    }
    case 150:
    {
        // fcmpg
        break;
    }
    case 151:
    {
        // dcmpl
        break;
    }
    case 152:
    {
        // dcmpg
        break;
    }
    case 153:
    {
        // ifeq

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 154:
    {
        // ifne

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 155:
    {
        // iflt

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 156:
    {
        // ifge

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 157:
    {
        // ifgt

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 158:
    {
        // ifle

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 159:
    {
        // if_icmpeq

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 160:
    {
        // if_icmpne

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 161:
    {
        // if_icmplt

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 162:
    {
        // if_icmpge

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 163:
    {
        // if_icmpgt

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 164:
    {
        // if_icmple

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 165:
    {
        // if_acmpeq

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 166:
    {
        // if_acmpne

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 167:
    {
        // goto

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 168:
    {
        // jsr

        int16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 169:
    {
        // ret

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 170:
    {
        // tableswitch
        unimplemented;
        break;
    }
    case 171:
    {
        // lookupswitch
        unimplemented;
        break;
    }
    case 172:
    {
        // ireturn
        break;
    }
    case 173:
    {
        // lreturn
        break;
    }
    case 174:
    {
        // freturn
        break;
    }
    case 175:
    {
        // dreturn
        break;
    }
    case 176:
    {
        // areturn
        break;
    }
    case 177:
    {
        // return
        break;
    }
    case 178:
    {
        // getstatic

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 179:
    {
        // putstatic

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 180:
    {
        // getfield

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 181:
    {
        // putfield

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 182:
    {
        // invokevirtual

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 183:
    {
        // invokespecial

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 184:
    {
        // invokestatic

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 185:
    {
        // invokeinterface

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;

        uint8 second;
        READB(second);
        out.args[1].value       = second;
        out.args[1].exists      = true;
        out.args[1].is_unsigned = true;

        uint8 third;
        READB(third);
        out.args[2].value       = third;
        out.args[2].exists      = true;
        out.args[2].is_unsigned = true;
        break;
    }
    case 186:
    {
        // invokedynamic

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;

        uint8 second;
        READB(second);
        out.args[1].value       = second;
        out.args[1].exists      = true;
        out.args[1].is_unsigned = true;

        uint8 third;
        READB(third);
        out.args[2].value       = third;
        out.args[2].exists      = true;
        out.args[2].is_unsigned = true;
        break;
    }
    case 187:
    {
        // new

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 188:
    {
        // newarray

        uint8 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 189:
    {
        // anewarray

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 190:
    {
        // arraylength
        break;
    }
    case 191:
    {
        // athrow
        break;
    }
    case 192:
    {
        // checkcast

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 193:
    {
        // instanceof

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 194:
    {
        // monitorenter

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 195:
    {
        // monitorexit

        uint16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = true;
        break;
    }
    case 196:
    {
        // wide
        unimplemented;
        break;
    }
    case 197:
    {
        // multianewarray

        int16 first;
        READB(first);
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;

        uint8 second;
        READB(second);
        out.args[1].value       = second;
        out.args[1].exists      = true;
        out.args[1].is_unsigned = true;
        break;
    }
    case 198:
    {
        // ifnull

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 199:
    {
        // ifnonnull

        int16 first;
        READB(first);
        first += (int16) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 200:
    {
        // goto_w

        int32 first;
        READB(first);
        first += (int32) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    case 201:
    {
        // jsr_w

        int32 first;
        READB(first);
        first += (int32) offset;
        out.args[0].value       = first;
        out.args[0].exists      = true;
        out.args[0].is_unsigned = false;
        break;
    }
    default:
        return false;
    }
    return true;
}
} // namespace GView::Java