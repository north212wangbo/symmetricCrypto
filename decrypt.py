#!/usr/bin/python

import sys
import binascii
from blockCipher import blockCipher

def readInput():
    	filename = sys.argv[1]
    	fd = open(filename, "rU")
    	text = fd.read()
    	charList = list(text)
    	blocks = []
    	i = 0
    	for char in charList:
		if (i % 16 == 0):
			newBlock = []
		newBlock.append(char)
		if (i % 16 == 15):
			blocks.append(newBlock)
		i+=1
    	return blocks

def main():
	f = open('decrypted.txt','w')
	key = int(sys.argv[2],16)
    	myBlockDecryptCipher = blockCipher(key)
    	myBlockDecryptCipher.blocks = readInput()

   	for block in myBlockDecryptCipher.blocks:
		myBlockDecryptCipher.block = int(''.join(block),16)
    		myBlockDecryptCipher.whitening()
		myBlockDecryptCipher.subkeyGenerator()
		myBlockDecryptCipher.round = 19
		for i in range(0,20):				
			myBlockDecryptCipher.fFunction()
			previousR0 = myBlockDecryptCipher.r0
                	previousR1 = myBlockDecryptCipher.r1
			myBlockDecryptCipher.r0 = myBlockDecryptCipher.leftRotate16bitsR2() ^ 	myBlockDecryptCipher.F0
			myBlockDecryptCipher.r1 = myBlockDecryptCipher.rightRotate16bitsR3()
			myBlockDecryptCipher.r2 = previousR0
			myBlockDecryptCipher.r3 = previousR1
		
			#print "round", myBlockDecryptCipher.round, format(myBlockDecryptCipher.r0,"04x"),format(myBlockDecryptCipher.r1,"04x"),format(myBlockDecryptCipher.r2,"04x"),format(myBlockDecryptCipher.r3,"04x")
			myBlockDecryptCipher.round -= 1

		plaintext = myBlockDecryptCipher.outputWhitening()
		#print 'Plaintext after 20 rounds',format(myBlockDecryptCipher.C0,"04x"),format(myBlockDecryptCipher.C1,"04x"),format(myBlockDecryptCipher.C2,"04x"),format(myBlockDecryptCipher.C3,"04x")	
		#print format(myBlockDecryptCipher.C0,"04x").decode("hex"),format(myBlockDecryptCipher.C1,"04x").decode("hex"),format(myBlockDecryptCipher.C2,"04x").decode("hex"),format(myBlockDecryptCipher.C3,"04x").decode("hex")
		f.write(format(myBlockDecryptCipher.C0,"04x").decode("hex")+format(myBlockDecryptCipher.C1,"04x").decode("hex")+format(myBlockDecryptCipher.C2,"04x").decode("hex")+format(myBlockDecryptCipher.C3,"04x").decode("hex"))
if __name__== '__main__':
    main()
