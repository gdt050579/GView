def GetCharType(i):
	# space = 0
	if (i==32) or (i==ord('\t')) or (i==13) or (i==10) or (i==0): return 0;	
	# group 1 --> letters
	if i>=ord('A') and i<=ord('Z'): return 1
	if i>=ord('a') and i<=ord('z'): return 1
	if i>=ord('0') and i<=ord('9'): return 1
	if (i==ord('-')) or (i==ord('_')): return 1
	# group 2
	if i<32: return 2
	# rest of the groups will receive the same value os i
	return i


s = "uint8 CharsGroups[128] = {"
for i in range(0,128):
	s += str(GetCharType(i))+","
s = s[:-1]+"};"
print(s)

#print(GetCharType(ord(',')))
