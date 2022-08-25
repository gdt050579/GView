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


def ComputeHash(text,devider):
	sum = 0
	index = 0
	for k in text:
		if ord(k)<=32:
			raise "Invali character in "+text
		sum = ((sum<<5) + ((ord(k)-32) & 0xFF))
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
	global op
	devider = ComputeHashes()
	l = ["None"]*devider
	s = "namespace OperatorType {\n"
	op_id = 0
	for k in op:
		l[ComputeHash(k,devider)] = op[k]	
		s += "constexpr uint32 "+op[k]+" = "+str(op_id)+";\n"
		op_id+=1
	s+="}\n"		        
	s+="namespace Operators {\n"                                        	
	s+= "constexpr uint32 HASH_DEVIDER = "+str(devider)+";\n"
	s+= "uint32 operator_hash_table[HASH_DEVIDER] = {";
	for k in l:
		if k=="None":
			s+="TokenType::None,"
		else:
			s+="TokenType::Operator | (OperatorType::"+k+"<<16),"
	s = s[:-1]+"};\n"	
	s+="}\n"
	print(s)
	
CreateHashTable()


ComputeHashes()		                
		
	        	