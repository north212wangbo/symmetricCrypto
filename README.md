Name: Bo Wang
Email: bo.wang@email.wsu.edu

Description: A public-key cryptosystem. Coded in Python, use 33bits modulo and 32bits block.

To Run:
- Put some text in 'ptext.txt', if not provided any, there's some old text in that file. 
- In terminal, in the 'file' directory, type: python publicKeyCrypto.py
- Each time, select successively 'Key Generation', 'Encrypt', 'Decrypt' by typing a number
- The decrypted message will be stored in 'dtext.txt'

List of files:
1. README.txt
2. ptext.txt (where the plain text is stored)
3. dtext.txt (where the decrypted message is stored)
4. pubkey.txt (store one's public key with form "prime,generator,public key")
5. prikey.txt (store one's private key with form "prime,generator,private key")
6. ctext.txt (where the encrypted messages is stored)
7. publicKeyCrypto.py (main program)
8. keyGenerator.py (component for generating keys)
9. Encryption.py (component for encryption)
10. Decryption.py (component for decryption)
