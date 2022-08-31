op = {
	">"	:"Bigger",
	"<"	:"Smaller",
	"="	:"Assign",
	">="	:"BiggerOrEq",
	"<="	:"SmallerOrEQ",
	"=="	:"Equal",
	"!="	:"Different",
	"+"	:"Plus",
	"-"	:"Minus",
	"*"	:"Multiply",
	"/"	:"Division",
	"%"	:"Modulo",
	"."	:"MemberAccess",
	"->"	:"Pointer",
	"++"	:"Increment",
	"--"	:"Decrement",
	"&&"	:"LogicAND",
	"||"	:"LogicOR",
	"&"	:"AND",
	"|"	:"OR",
	"^"	:"XOR",
	"!"	:"LogicNOT",
	"~"	:"NOT",
	"?"	:"Condition",
	":"	:"TWO_POINTS",
	"::"	:"Namespace",
	"+="	:"PlusEQ",
	"-="	:"MinusEQ",
	"*="	:"MupliplyEQ",
	"/="	:"DivisionEQ",
	"%="	:"ModuloEQ",
	"&="	:"AndEQ",
	"|="	:"OrEQ",
	"^="	:"XorEQ",
	"<<"	:"LeftShift",
	">>"	:"RightShift",
	">>="	:"RightShiftEQ",
	"<<="	:"LeftShiftEQ",
	"<=>"	:"Spaceship"
}

def ComputeCharIndexes():
	global op
	d = {}
	for k in op:
		for ch in k:
			if not ch in d:
				d[ch] = len(d)+1
	return d

chIndex = ComputeCharIndexes()
 
def ComputeHash(text,devider):
	global chIndex
	sum = 0
	index = 0
	for k in text:
		if not k in chIndex:
			raise "Invalid character in "+text
		sum = (sum<<5)+chIndex[k]
		index+=1
	return sum % devider

def ComputeHashes():
	global op
	devider = len(op)
	while True:
		#print("Searcing devider: "+str(devider))
		d = {}
		for k in op:
			hash = ComputeHash(k, devider)
			if hash in d:
				#print("Colision for "+k+" with "+d[hash])
				break
			d[hash] = k
		if len(d)==len(op):
			break
		devider+=1
	print("Found devider: "+str(devider)+" for "+str(len(op))+" elements")
	return devider

def CreateHashTable():
	global op,chIndex
	devider = ComputeHashes()
	l = [("None",0)]*devider
	s = "namespace OperatorType {\n"
	op_id = 0
	for k in op:
		l[ComputeHash(k,devider)] = (op[k],ComputeHash(k,0xFFFFFFFF))	
		s += "constexpr uint32 "+op[k]+" = "+str(op_id)+";\n"
		op_id+=1
	s+="}\n"		        
	s+="namespace Operators {\n"                                        	
	s+="uint8 chars_ids[128] = {";
	for i in range(0,128):
		if chr(i) in chIndex:
			s+=str(chIndex[chr(i)])+","
		else:
			s+="0,"
	s = s[:-1]+"};\n"	
	s+= "constexpr uint32 HASH_DEVIDER = "+str(devider)+";\n"
	s+= "uint32 operator_hash_table[HASH_DEVIDER] = {";
	for k in l:
		print(k)
		if k[0]=="None":
			s+="TokenType::None,"
		else:
			s+="(uint32)TokenType::Operator | (uint32)(OperatorType::"+k[0]+"<<8) | (uint32)("+str(k[1])+" << 16),"
	s = s[:-1]+"};\n"	
	s+="}\n"
	print(s)
	
ComputeHashes()		                
CreateHashTable()
		

	        	