# -*- coding: utf-8 -*-
"""
Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?
"""

from Crypto.Cipher import AES
from s2_9 import padToLen
from set1_6Helper import getListOfChunks
from s1_2 import xor
import base64
from set1_4 import readAllLinesFromFile


def padToBeAMultipleOfN(content, n):
    #get last block index
    indexesOfBlocksOfNMult = range(0, len(content), n)
    lastBlockIndex = indexesOfBlocksOfNMult[-1]
    #get last block and pad it
    lastBlock = content[lastBlockIndex:len(content)]
    lastBlockPadded = padToLen(lastBlock, n)
    #return a new byte array with the content padded
    paddedContent = bytearray(content[0:lastBlockIndex])
    paddedContent.extend(lastBlockPadded)
    return bytes(paddedContent);

#this class also pads the content befor the encryption 
#so the decryption will be padded aswell
class AES128ECBCipher:
    
    def __init__(self, key):
        self.key = key;
        self.aES128ECB = AES.new(self.key, AES.MODE_ECB);
          
    def encrypt(self, content):
        return self.aES128ECB.encrypt(padToBeAMultipleOfN(content, 16));
        
    def decrypt(self, content):
        return self.aES128ECB.decrypt(content)
    
class AES128CBCCipher:
    
    def __init__(self, key, IV):
        self.key = key;
        self.IV = IV;
        self.aES128ECB = AES128ECBCipher(key);
    
    def encrypt(self, content):
        #prepare 
        paddedContent = padToBeAMultipleOfN(content, 16)
        contentBlocks =  getListOfChunks(paddedContent, 16)
        #encrypt
        encryptedBlocks = [self.aES128ECB.encrypt(xor(self.IV, contentBlocks[0]))]#first block with special care
        for contentBlock in contentBlocks[1:]:
            lastEncryptedBlock = encryptedBlocks[-1]
            contentToEncrypt = xor(lastEncryptedBlock, contentBlock)
            assert(len(contentToEncrypt) == 16)
            encryptedContent = self.aES128ECB.encrypt(contentToEncrypt)
            assert(len(encryptedContent) == 16)
            encryptedBlocks.append(encryptedContent)
        #finish (concat the list of encrypted blocks to one big continuous line)
        encryptedContent = bytearray()
        list(map(encryptedContent.extend, encryptedBlocks));
        return bytes(encryptedContent);
        
    def decrypt(self, encryptedContent):
        semiDecryptedContent = self.aES128ECB.decrypt(encryptedContent) #still with the xor of the chaining thing
        #gettint the xor chain thing
        xorAndDone = bytearray(self.IV)
        xorAndDone.extend(encryptedContent[:-16])
        decryptedContent = xor(semiDecryptedContent, xorAndDone)
        return decryptedContent
    
def readAllFileToOneLine(fpath):
    content = readAllLinesFromFile(fpath)
    contentOneLine = ''.join(content)
    return contentOneLine

def s2_10main():
    IV  = bytes([0]*16)
    key = bytes("YELLOW SUBMARINE", "utf-8")
    
    fpath = "C:\\Programming\\pythonWorkspaces\\cryptopalsWorkspace\\set1\\10.txt"
    encryptedContent64 = readAllFileToOneLine(fpath)
    encryptedContent = base64.b64decode(encryptedContent64)
    
    cbcCypher = AES128CBCCipher(key, IV)
    decryptedContent = cbcCypher.decrypt(encryptedContent)
    print(decryptedContent)

#yNoWork = AES.new(key, AES.MODE_CBC, IV)


"""
oneBlockCypher = AES128ECBCipher(key);

etmp = oneBlockCypher.encrypt(content)
print(etmp)
print(oneBlockCypher.decrypt(etmp))



IV  = bytes("fake 0th ciphert", "utf-8")
key = bytes("YELLOW SUBMARINE", "utf-8")
content = bytes("Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.", "utf-8")

cbcCypher = AES128CBCCipher(key, IV)
encryptedContent = cbcCypher.encrypt(content)
print(encryptedContent)
print('')
decryptedContent = cbcCypher.decrypt(encryptedContent)
print(decryptedContent)
"""

