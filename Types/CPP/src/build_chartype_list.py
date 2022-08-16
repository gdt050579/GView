def GetCharType(ch):
	if ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_":
		return "Word"
	if ch in "0123456789":
		return "Number"
	if (ch==' ') or (ch=='\t') or (ch=='\n') or (ch=='\r'):
		return "Space"
	if ch=='#':
		return "Preprocess"
	if ch in "!%+-=^&|*:?~\/":
		return "Operator"
	if ch == '{':
		return "BlockOpen"
	if ch == '}':
		return "BlockClose"
	if ch == '[':
		return "ArrayOpen"
	if ch == ']':
		return "ArrayClose"
	if ch == '(':
		return "ExpressionOpen"
	if ch == ')':
		return "ExpressionClose"
	if ch==',':
		return "Comma"
	if ch==';':
		return "Semicolumn"
	if (ch=='\"') or (ch=='\''):
		return "String"
	return "Invalid"

s = "uint8 Cpp_Groups_IDs[] = {"
for i in range(0,128):
	s += GetCharType(chr(i))+","
s = s[:-1]+"};"
print(s)                                                                     
