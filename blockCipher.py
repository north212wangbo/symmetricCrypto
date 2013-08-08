import binascii
import sys

class blockCipher:
	def __init__(self, key):
		self.key = key
		self.blocks = []
		self.block = 0
		self.round = 0
		self.r0 = 0
		self.r1 = 0
		self.r2 = 0
		self.r3 = 0
		self.C0 = 0
		self.C1 = 0
		self.C2 = 0
		self.C3 = 0
		self.F0 = 0
		self.F1 = 0
		self.allSubkey = []
		self.keyIter = 0
		self.ftable = [0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
			0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
			0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
			0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
			0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
			0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
			0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
			0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
			0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
			0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
			0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
			0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
			0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
			0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
			0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
			0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46]
		

	def whitening(self):
		whiteningKey = self.key / 2**16
    		output = list(format(whiteningKey ^ self.block,"016x"))
    		#print output
    		self.r0 = int(''.join(output[0:4]),16)
    		self.r1 = int(''.join(output[4:8]),16)
   		self.r2 = int(''.join(output[8:12]),16)
   		self.r3 = int(''.join(output[12:16]),16)
		#print self.r0, self.r1, self.r2, self.r3
   		return

	def outputWhitening(self):
		whiteningKey = self.key / 2**16
   		key = format(whiteningKey,"064b")
    		K0 = int(''.join(key[0:16]),2)
    		K1 = int(''.join(key[16:32]),2)
    		K2 = int(''.join(key[32:48]),2)
    		K3 = int(''.join(key[48:64]),2)
    		self.C0 = self.r2 ^ K0
    		self.C1 = self.r3 ^ K1
    		self.C2 = self.r0 ^ K2
    		self.C3 = self.r1 ^ K3
    		return
    
	def keySchedule(self,input):
    		self.key = self.leftRotate80bitsKey(format(self.key,"080b"))		
    		key1 = format(self.key,"080b")
    		subkey = list(key1)
    		k = []
    		k.append(subkey[72:80])
    		k.append(subkey[64:72])
    		k.append(subkey[56:64])
    		k.append(subkey[48:56])
    		k.append(subkey[40:48])
    		k.append(subkey[32:40])
    		k.append(subkey[24:32])
    		k.append(subkey[16:24])
		k.append(subkey[8:16])
		k.append(subkey[0:8])
    		result = ''.join(k[input % 10])
    		output = int(result,2)
		
    		return output

	def subkeyGenerator(self):
		for i in range (0,20):
			subkey = []
			for j in range (0,3):			
				subkey.append(self.keySchedule(4*i))
				subkey.append(self.keySchedule(4*i+1))
				subkey.append(self.keySchedule(4*i+2))
				subkey.append(self.keySchedule(4*i+3))
			self.allSubkey.append(subkey)
		#print self.allSubkey
		return
			
	def leftRotate80bitsKey(self,input):
    		characters = list(input)
    		characters += characters
    		result = ''.join(characters[1:81])
    		output = int(result,2)
    		return output

	def rightRotate16bitsR2(self):
		inputInt = self.r2 ^ self.F0
    		inputInt = format(inputInt,"016b")
    		characters = list(inputInt)
    		characters += characters
    		result = ''.join(characters[15:31])
    		output = int(result,2)
    		return output

	def rightRotate16bitsR3(self):
		inputInt = self.r3 ^ self.F1
    		inputInt = format(inputInt,"016b")
    		characters = list(inputInt)
    		characters += characters
    		result = ''.join(characters[15:31])
    		output = int(result,2)
    		return output

	def leftRotate16bitsR2(self):
		inputInt = self.r2
    		inputInt = format(inputInt,"016b")
    		characters = list(inputInt)
    		characters += characters
    		result = ''.join(characters[1:17])
    		output = int(result,2)
    		return output

	def leftRotate16bitsR3(self):
		inputInt = self.r3
    		inputInt = format(inputInt,"016b")
    		characters = list(inputInt)
    		characters += characters
    		result = ''.join(characters[1:17])
    		output = int(result,2)
    		return output

	def gpermutation(self,r):
    		r = format(r,"04x")
    		w = list(r)
    		g1 = w[0:2]
    		g2 = w[2:4]
    		g1 = int(''.join(g1),16)
    		g2 = int(''.join(g2),16)
    
    		g3 = self.ftable[g2 ^ self.allSubkey[self.round][self.keyIter]] ^ g1
		self.keyIter += 1
    		g4 = self.ftable[g3 ^ self.allSubkey[self.round][self.keyIter]] ^ g2
		self.keyIter += 1
    		g5 = self.ftable[g4 ^ self.allSubkey[self.round][self.keyIter]] ^ g3
		self.keyIter += 1
    		g6 = self.ftable[g5 ^ self.allSubkey[self.round][self.keyIter]] ^ g4
		self.keyIter += 1
    		g5 = format(g5,"08b")
    		g6 = format(g6,"08b")
    		#print g1,g2,g3,g4,g5,g6
    		result = int(g5+g6,2)
    		return result

	def fFunction(self):
    		t0 = self.gpermutation(self.r0)
    		t1 = self.gpermutation(self.r1)
    		K1 = format(self.allSubkey[self.round][self.keyIter],"08b")
		self.keyIter += 1
    		K2 = format(self.allSubkey[self.round][self.keyIter],"08b")
		self.keyIter += 1
    		K3 = format(self.allSubkey[self.round][self.keyIter],"08b")
		self.keyIter += 1
    		K4 = format(self.allSubkey[self.round][self.keyIter],"08b")
		self.keyIter += 1
    		concaten1 = int((K1 + K2),2)
    		concaten2 = int((K3 + K4),2)
    		self.F0 = (t0 + 2*t1 + concaten1) % 2**16
    		self.F1 = (2*t0 + t1 + concaten2) % 2**16
		#print self.F0, self.F1
		self.keyIter = 0
    		return 	
