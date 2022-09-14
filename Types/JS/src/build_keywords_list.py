                                                                                                                                                                          
keywords = ["abstract","break","case", "catch", "class","continue", "const", "console", "debugger", "default","delete", "do","double", "else","enum", "export","extends","final", "finally", "for","function", "goto","if", "implements","import", "in","instanceof","interface","native", "new", "package","private", "protected","public", "return", "static","super", "switch","synchronized", "this","throw", "throws","transient","try", "typeof","while", "with","alert", "arguments","Array", "blur", "callee","caller", "captureEvents","clearInterval", "clearTimeout","close", "closed","confirm", "constructor","Date", "defaultStatus","document", "escape","eval", "find","focus", "frames", "history","home", "Infinity","innerHeight", "innerWidth","isFinite", "isNaN","java", "length","location", "locationbar","Math", "menubar","moveBy", "name", "netscape", "open", "opener","outerHeight", "outerWidth","Packages", "pageXOffset","pageYOffset", "parent","parseFloat", "parseInt","personalbar", "print","prompt", "prototype","RegExp", "releaseEvents","resizeBy", "resizeTo","routeEvent", "scroll","scrollbars", "scrollBy","scrollTo", "self","setInterval", "setTimeout","status", "statusbar","stop","toolbar", "top","toString", "unescape","unwatch", "valueOf","watc","win"]


data_type = ["Boolean", "byte", "char", "float", "int", "long", "short","var", "void", "let", "Number", "String", "Object"]

constants = ["false", "true", "null", "NaN"]

def ComputeHash(text):
	text = text.lower()
	hash = 0x811c9dc5
	for c in text:
		hash = (hash ^ (ord(c) & 0xFF)) & 0xFFFFFFFF;
		hash = (hash * 0x01000193) & 0xFFFFFFFF;
	return hash & 0xFFFFFFFF;



def CreateList(l, name, start_index, end_index):
	res = []
	for k in l:
		res += [(ComputeHash(k),k)]
	res.sort(key = lambda x: x[0])
	idx = start_index
	s = "// To be added in TokenTyepe namespace\n"
	for k in res:
		s += "\tconstexpr uint32 "+ name + "_"+k[1][0].upper()+k[1][1:].lower()+" = "+str(idx)+";\n"
		idx+=1
	s+= "\n"
	s+= "inline bool Is" + name + "(uint32 tokenType) { return (tokenType >= " + str(start_index) + " && tokenType <= " + str(end_index) + ");}\n"
	s+= "namespace "+name+" {\n"
	s += "\tuint32 list[] = {\n";
	for k in res:
		s+="0x%08X"%(k[0])+","
	s+="\t};\n"
	s+="\tuint32 TextTo"+name+"ID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end) {\n"
	s+="\t\tauto res = BinarySearch(text.ComputeHash32(start,end,false),list,"+str(len(res))+");\n"
	s+="\t\tif (res == -1) return TokenType::None;\n"
	s+="\t\treturn "+str(start_index) + " + res;\n"
	s+="\t};\n"
	s+="}\n"
	print(s)

#CreateList(keywords,"Keyword", 1000, 5000)
#CreateList(data_type,"Datatype", 6000, 7000)
CreateList(constants,"Constant", 8000, 9000)