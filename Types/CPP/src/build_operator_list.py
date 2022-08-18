op = {
	">"	:"BIGGER",
	"<"	:"SMALLER",
	"="	:"ASSIGN",
	">="	:"BIGGER_EQ",
	"<="	:"SMALLER_EQ",
	"=="	:"EQUAL",
	"!="	:"DIFFERENT",
	"+"	:"PLUS",
	"-"	:"MINUS",
	"*"	:"MULTIPLY",
	"/"	:"DIVISION",
	"%"	:"MODULO",
	"."	:"MEMBER",
	"->"	:"POINTER",
	"++"	:"INCREMENT",
	"--"	:"DECREMENT",
	"&&"	:"LOGIC_AND",
	"||"	:"LOGIC_OR",
	"&"	:"AND",
	"|"	:"OR",
	"^"	:"XOR",
	"!"	:"LOGIC_NOT",
	"~"	:"NOT",
	"?"	:"CONDITION",
	":"	:"TWO_POINTS",
	"::"	:"NAMESPACE",
	"+="	:"PLUS_EQ",
	"-="	:"MINUS_EQ",
	"*="	:"MUL_EQ",
	"/="	:"DIV_EQ",
	"%="	:"MODULO_EQ",
	"&="	:"AND_EQ",
	"|="	:"OR_EQ",
	"^="	:"XOR_EQ",
	"<<"	:"LEFT_SHIFT",
	">>"	:"RIGHT_SHIFT",
	">>="	:"RIGHT_SHIFT_EQ",
	"<<="	:"LEFT_SHIFT_EQ",
	"<=>"	:"SPACESHIP"
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
	s = ""
	op_id = 100
	for k in op:
		l[ComputeHash(k,devider)] = "Operator"+op[k]	
		s += "constexpr uint32 Operator"+op[k]+" = "+str(op_id)+";\n"
		op_id+=1
		        
	s+="namespace Operators {\n"                                        	
	s+= "constexpr uint32 HASH_DEVIDER = "+str(devider)+";\n"
	s+= "uint32 operator_hash_table[HASH_DEVIDER] = {";
	for k in l:
		s+="TokenType::"+k+","
	s = s[:-1]+"};\n"	
	s+="}\n"
	print(s)
	
CreateHashTable()


ComputeHashes()		                
		
	        	