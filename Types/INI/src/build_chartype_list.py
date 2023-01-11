def GetCharType(ch):
	if (ch==ord(' ')) or (ch==ord('\t')) or (ch==ord('\n')) or (ch==ord('\r')):
		return "SpaceOrNewLine"
	if (ch==ord('=')) or (ch==ord(':')):
		return "Equal"
	if (ch==ord('"')) or (ch==ord('\'')):
		return "String"
	if (ch==ord(';')) or (ch==ord('#')):
		return "Comment"
	if (ch==ord(',')):
		return "Comma"
	if (ch==ord('[')):
		return "SectionOrArrayStart"
	if (ch==ord(']')):
		return "SectionOrArrayEnd"
	if (ch>32):
		return "Word"
	return "Invalid"

s = "uint8 Ini_Groups_IDs[] = {"
for i in range(0,128):
	s += GetCharType(i)+","
s = s[:-1]+"};"
print(s)
