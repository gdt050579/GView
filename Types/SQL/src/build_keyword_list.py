sql_keywords = [
    "select","insert","update","delete","merge",
    "from","where","group","having","order","by",
    "join","inner","left","right","full","cross","on","using",
    "union","intersect","except",
    "distinct","all",
    "as","and","or","not",
    "in","exists","between","like","is","null",
    "case","when","then","else","end",
    "create","alter","drop","truncate",
    "table","view","index","schema","database",
    "primary","key","foreign","references","unique","check","constraint",
    "default","generated","identity",
    "values","set","into",
    "limit","offset","fetch",
    "over","partition","window",
    "cast","coalesce","nullif",
    "begin","commit","rollback","savepoint","transaction",
    "grant","revoke","privileges","public",
    "explain","analyze",
    "true","false","unknown",
    "with","recursive"
]

sql_datatypes = [
    # Integer-ish
    "smallint","integer","int","bigint",
    "serial","bigserial",
    # Exact numeric
    "numeric","decimal",
    # Approx numeric
    "real","float","double","doubleprecision",
    # Character
    "char","character","varchar","character_varying","text","nchar","nvarchar",
    # Binary
    "binary","varbinary","blob","bytea",
    # Boolean
    "boolean","bool",
    # Date/time
    "date","time","timetz","timestamp","timestamptz","datetime","interval",
    # UUID / JSON (very common)
    "uuid","json","jsonb",
    # Misc
    "xml"
]

sql_constants = [
    "null","true","false"
]

def ComputeSQLHash(text: str) -> int:
    text = text.lower()
    h = 0x811c9dc5
    for c in text:
        h = (h ^ (ord(c) & 0xFF)) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h & 0xFFFFFFFF

def CreateSQLList(l, name):

    res = []
    for k in l:
        res += [(ComputeSQLHash(k), k)]
    res.sort(key=lambda x: x[0])

    idx = 0
    s = "namespace " + name + "sType {\n"
    for k in res:
        cpp_id = k[1][0].upper() + k[1][1:].lower()
        s += "\tconstexpr uint32 " + cpp_id + " = " + str(idx) + ";\n"
        idx += 1
    s += "}\n"
    s += "namespace " + name + " {\n"
    s += "\tHashText list[] = {\n"
    for k in res:
        cpp_id = k[1][0].upper() + k[1][1:].lower()
        s += "\t\t{0x%08X" % (k[0]) + "," + name + "sType::" + cpp_id + "},\n"
    s += "\t};\n"
    s += "\tuint32 TextTo" + name + "ID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end) {\n"
    s += "\t\tauto *res = BinarySearch(text.ComputeHash32(start,end,false),list," + str(len(res)) + ");\n"
    s += "\t\tif (res == nullptr) return TokenType::None;\n"
    s += "\t\treturn TokenType::" + name + " | (res->id << 16);\n"
    s += "\t};\n"
    s += "}\n"
    print(s)

#CreateSQLList(sql_keywords,  "Keyword")
CreateSQLList(sql_datatypes, "Datatype")
#CreateSQLList(sql_constants, "Constant")
