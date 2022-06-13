def GetCharType(i):
	if i>=ord('A') and i<=ord('Z'): return "true"
	if i>=ord('a') and i<=ord('z'): return "true"
	if i>=ord('0') and i<=ord('9'): return "true"
	if (i==32) or (i==ord('\t')): return "true"
	if (chr(i) in " .\t\\,.():*-+=_/'\"%$!@#&"): return "true"
	return "false"


s = "bool DefaultAsciiMask[256] = {"
for i in range(0,256):
	s += GetCharType(i)+","
s = s[:-1]+"};"
print(s)

#print(GetCharType(ord(',')))
