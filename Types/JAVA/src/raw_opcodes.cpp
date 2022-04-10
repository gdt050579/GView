#include "global.hpp"

namespace GView::Java
{
bool print_opcodes(BufferView buffer)
{
    BufferReader reader(buffer.GetData(), buffer.GetLength());
    while (!reader.done())
    {
        uint8 opcode;
        READB(opcode);

        switch (opcode)
        {
        case 18:
        {
            uint8 arg_0;
            READB(arg_0);
            printf("ldc\n");
            break;
        }
        case 19:
        {
            uint16 arg_0;
            READB(arg_0);
            printf("ldc_w\n");
            break;
        }
        case 20:
        {
            uint16 arg_0;
            READB(arg_0);
            printf("ldc2_w\n");
            break;
        }
        case 25:
        {
            uint8 arg_0;
            READB(arg_0);
            printf("aload\n");
            break;
        }
        case 42:
        {
            printf("aload_0\n");
            break;
        }
        case 43:
        {
            printf("aload_1\n");
            break;
        }
        case 44:
        {
            printf("aload_2\n");
            break;
        }
        case 45:
        {
            printf("aload_3\n");
            break;
        }
        case 172:
        {
            printf("ireturn\n");
            break;
        }
        case 173:
        {
            printf("lreturn\n");
            break;
        }
        case 174:
        {
            printf("freturn\n");
            break;
        }
        case 175:
        {
            printf("dreturn\n");
            break;
        }
        case 176:
        {
            printf("areturn\n");
            break;
        }
        case 177:
        {
            printf("return\n");
            break;
        }
        case 178:
        {
            uint16 arg_0;
            READB(arg_0);
            printf("getstatic\n");
            break;
        }
        case 182:
        {
            uint16 arg_0;
            READB(arg_0);
            printf("invokevirtual\n");
            break;
        }
        case 183:
        {
            uint16 arg_0;
            READB(arg_0);
            printf("invokespecial\n");
            break;
        }
        case 184:
        {
            uint16 arg_0;
            READB(arg_0);
            printf("invokestatic\n");
            break;
        }
        case 185:
        {
            uint16 arg_0;
            READB(arg_0);
            uint8 arg_1;
            READB(arg_1);
            uint8 arg_2;
            READB(arg_2);
            printf("invokeinterface\n");
            break;
        }
        case 186:
        {
            uint16 arg_0;
            READB(arg_0);
            uint8 arg_1;
            READB(arg_1);
            uint8 arg_2;
            READB(arg_2);
            uint8 arg_3;
            READB(arg_3);
            printf("invokedynamic\n");
            break;
        }
        default:
            unimplemented;
            return false;
        }
    }
    return true;
}
} // namespace GView::Java