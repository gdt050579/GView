
keywords = ["alignas", "alignof", "asm", "atomic_cancel", "atomic_commit", "atomic_noexcept", "auto", "break","case","catch", 
	    "class","compl", "concept", "const", "consteval", "constexpr", "constinit", "const_cast", "continue", "co_await", 
            "co_return", "co_yield", "decltype", "default", "delete", "do","dynamic_cast","else","enum","explicit","export",
	    "extern", "for","friend","goto","if","inline","mutable", "namespace", "new", "noexcept","operator","private",
            "protected","public","reflexpr","register","reinterpret_cast","requires","return", "sizeof", "static", "static_assert", 
            "static_cast", "struct", "switch", "synchronized", "template", "this", "thread_local", "throw", "try", "typedef", 
            "typeid", "typename", "union", "using","virtual","volatile","while", "final","override","transaction_safe","transaction_safe_dynamic","import","module"]


"""
bool
char
char8_t (C++20)
char16_t (C++11)
char32_t (C++11)
double
false
float
int
long
nullptr (C++11)
short
signed
true
unsigned
void

wchar_t

"""

def ComputeHash(text):
	text = text.lower()
	hash = 0x811c9dc5
	for c in text:
		hash = (hash ^ (ord(c) & 0xFF)) & 0xFFFFFFFF;
		hash = (hash * 0x01000193) & 0xFFFFFFFF;
	return hash & 0xFFFFFFFF;



def CreateList(l, name):
	res = []
	for k in l:
		res += [(ComputeHash(k),k)]
	res.sort(key = lambda x: x[0])
	idx = 0
	s = "namespace "+name+"sType {\n"
	for k in res:
		s += "\tconstexpr uint32 "+k[1][0].upper()+k[1][1:].lower()+" = "+str(idx)+";\n"
		idx+=1
	s+="}\n"
	s+= "namespace "+name+" {\n"
	s += "\tHashText list[] = {\n";
	for k in res:
		s+="\t\t{0x%08X"%(k[0])+","+name+"sType::"+k[1][0].upper()+k[1][1:].lower()+"},\n"
	s+="\t};\n"
	s+="\tuint32 TextTo"+name+"ID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end) {\n"
	s+="\t\tauto *res = BinarySearch(text.ComputeHash32(start,end,true),list,"+str(len(res))+");\n"
	s+="\t\tif (res == nullptr) return TokenType::None;\n"
	s+="\t\treturn TokenType::"+name+" | (res->id << 16);\n"
	s+="\t};\n"
	s+="}\n"
	print(s)

CreateList(keywords,"Keyword")