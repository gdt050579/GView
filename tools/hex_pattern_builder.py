def GetCharType(i):
	if i>=ord('A') and i<=ord('F'): return str(i-ord('A'))
	if i>=ord('a') and i<=ord('f'): return str(i-ord('a'))
	if i>=ord('0') and i<=ord('9'): return str(i-ord('0'))
	if (i==32) or (i==ord('\t')): return "CHAR_TYPE_SEP"
	if (i==',') or (i==ord(';')): return "CHAR_TYPE_SEP"
	if (i=='?'): return "CHAR_TYPE_ANY"
	return "CHAR_TYPE_INVALID"


s = "unsigned char PatternCharTypes[256] = {"
for i in range(0,256):
	s += GetCharType(i)+","
s = s[:-1]+"};"
print(s)
