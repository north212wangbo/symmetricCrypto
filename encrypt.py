#!/usr/bin/python

import sys
import binascii
from blockCipher import blockCipher

def readInput():
    filename = sys.argv[1]
    fd = open(filename, "rU")
    text = fd.read()
    charList = list(text)
    while (len(charList) % 16 != 0):
	charList.append('0')
    blocks = []
    i = 0
    for char in charList:
	if (i % 8 == 0):
		newBlock = []
	hexChar = format(ord(char),"02x")
	newBlock.append(hexChar)
	if (i % 8 == 7):			
		blocks.append(newBlock)
	i+=1
    return blocks
	
def main():
    f = open('ciphertext.txt','w')
    key = int(sys.argv[2],16)  
    myBlockEncryptCipher = blockCipher(key)
    myBlockEncryptCipher.blocks = readInput()

    for block in myBlockEncryptCipher.blocks:
    	myBlockEncryptCipher.block = int(''.join(block),16)	    
    	myBlockEncryptCipher.whitening()
    	myBlockEncryptCipher.subkeyGenerator()
    	for i in range (0,20):
    		myBlockEncryptCipher.fFunction()
    		temp = myBlockEncryptCipher.rightRotate16bitsR2()
    		myBlockEncryptCipher.r2 = myBlockEncryptCipher.r0
    		myBlockEncryptCipher.r0 = temp
    		r3_ = myBlockEncryptCipher.leftRotate16bitsR3()
    		temp = r3_ ^ myBlockEncryptCipher.F1
    		myBlockEncryptCipher.r3 = myBlockEncryptCipher.r1
    		myBlockEncryptCipher.r1 = temp
    		#print "round", myBlockEncryptCipher.round, format(myBlockEncryptCipher.r0,"04x"),format	(myBlockEncryptCipher.r1,"04x"),format(myBlockEncryptCipher.r2,"04x"),format(myBlockEncryptCipher.r3,"04x")
    		myBlockEncryptCipher.round += 1
   
    	ciphertext = myBlockEncryptCipher.outputWhitening()
    	#print 'Ciphertext after 20 rounds',format(myBlockEncryptCipher.C0,"04x"),format(myBlockEncryptCipher.C1,"04x"),format(myBlockEncryptCipher.C2,"04x"),format(myBlockEncryptCipher.C3,"04x")
	f.write(format(myBlockEncryptCipher.C0,"04x")+format(myBlockEncryptCipher.C1,"04x")+format(myBlockEncryptCipher.C2,"04x")+format(myBlockEncryptCipher.C3,"04x"))
	
if __name__== '__main__':
    main()
