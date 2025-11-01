def GetCharType(ch):
	if ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789!'%+-^&|*?~.":
		return "Text"
	if (ch==' ') or (ch=='\t') or (ch=='\n') or (ch=='\r'):
		return "Space"
	if ch == '<':
		return "StartTag"
	if ch == '>':
		return "EndTag"
	if ch == ':':
		return "Colon"
	if ch == '=':
		return "Equals"
	if ch=='\"':
		return "String"
	if ch == '/':
		return "Slash"
	return "Invalid"

s = "uint8 XML_Groups_IDs[] = {"
for i in range(0,128):
	s += GetCharType(chr(i))+","
s = s[:-1]+"};"
print(s)                                                                     
