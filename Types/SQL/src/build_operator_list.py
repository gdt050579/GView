op = {
    # Comparison
    ">"   : "Bigger",
    "<"   : "Smaller",
    "="   : "Equal",
    ">="  : "BiggerOrEq",
    "<="  : "SmallerOrEq",
    "<>"  : "Different",
    "!="  : "Different",

    # Arithmetic
    "+"   : "Plus",
    "-"   : "Minus",
    "*"   : "Multiply",
    "/"   : "Division",
    "%"   : "Modulo",

    # Punctuation-like operators you likely tokenize as Operator (or separate TokenType if you prefer)
    "."   : "MemberAccess",
    ","   : "Comma",
    ";"   : "Semicolumn",
    "("   : "ParenOpen",
    ")"   : "ParenClose",

    "||"  : "Concat",

    "::"  : "Cast",           # PostgreSQL type cast operator
    "->"  : "JsonArrow",      # PostgreSQL JSON operator
    "->>" : "JsonArrowText"   # PostgreSQL JSON text operator
}

def ComputeCharIndexes():
    global op
    d = {}
    for k in op:
        for ch in k:
            if ch not in d:
                d[ch] = len(d) + 1
    return d

chIndex = ComputeCharIndexes()

def ComputeHash(text, devider):
    global chIndex
    s = 0
    for k in text:
        if k not in chIndex:
            raise Exception("Invalid character in " + text)
        s = (s << 5) + chIndex[k]
    return s % devider

def ComputeHashes():
    global op
    devider = len(op)
    while True:
        d = {}
        for k in op:
            h = ComputeHash(k, devider)
            if h in d:
                break
            d[h] = k
        if len(d) == len(op):
            break
        devider += 1
    print("Found devider: " + str(devider) + " for " + str(len(op)) + " elements")
    return devider

def ComputeFNV1a32(text: str) -> int:
    h = 0x811c9dc5
    for c in text:
        h = (h ^ (ord(c) & 0xFF)) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h & 0xFFFFFFFF

def CreateHashTable():
    global op, chIndex
    devider = ComputeHashes()

    l = [("None", 0)] * devider

    s = "namespace OperatorType {\n"
    op_id = 0

    for k in op:
        l[ComputeHash(k, devider)] = (op[k], ComputeFNV1a32(k))

        s += "    constexpr uint32 " + op[k] + " = " + str(op_id) + ";\n"
        op_id += 1

    s += "} // namespace OperatorType\n\n"

    s += "namespace Operators {\n"
    s += "    uint8 chars_ids[128] = {"
    for i in range(0, 128):
        s += str(chIndex.get(chr(i), 0)) + ","
    s = s[:-1] + "};\n"

    s += "    constexpr uint32 HASH_DEVIDER = " + str(devider) + ";\n"
    s += "    uint32 operator_hash_table[HASH_DEVIDER] = {"

    for entry in l:
        if entry[0] == "None":
            s += "TokenType::None,"
        else:

            s += "(uint32)TokenType::Operator | (uint32)(OperatorType::" + entry[0] + "<<8) | (uint32)(" + str(entry[1]) + " << 16),"

    s = s[:-1] + "};\n"
    s += "} // namespace Operators\n"

    print(s)

ComputeHashes()
CreateHashTable()
