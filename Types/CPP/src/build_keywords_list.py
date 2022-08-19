
keywords = ["if","while","do"]

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
	s+="\tHashText* TextTo"+name+"ID(const GView::View::LexicalViewer::TextParser& text, uint32 start, uint32 end) {\n"
	s+="\t\treturn BinarySearch(text.ComputeHash32(start,end,true),list,"+str(len(res))+");\n"
	s+="\t};\n"
	s+="}\n"
	print(s)

CreateList(keywords,"Keyword")