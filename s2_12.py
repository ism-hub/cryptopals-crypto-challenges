# -*- coding: utf-8 -*-
"""
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
Detect that the function is using ECB. You already know, but do this step anyways.
Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.
Congratulations.
This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
"""

from s2_11 import generateNRandomeBytes, isEBCEcrypted
from s2_10 import AES128ECBCipher
import base64
from set1_6Helper import getListOfChunks

s2_12KEY = generateNRandomeBytes(16)
s2_12PREFIX = bytes() #for s2_14

def s2_12_AES_128_ECB(controlledContent):
    unknownContent = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    
    contentToEncrypt = bytearray(s2_12PREFIX)
    contentToEncrypt.extend(controlledContent)
    contentToEncrypt.extend(unknownContent)
    contentToEncrypt = bytes(contentToEncrypt)
    
    cbeCipher = AES128ECBCipher(s2_12KEY)
    encryptedContent = cbeCipher.encrypt(contentToEncrypt)
    return encryptedContent;
    
def discoverBlockSizeOfCipher():
    i = 2;
    while True:
        msgB4 = bytes('A'*i, "utf-8")
        encryptedMsg = s2_12_AES_128_ECB(msgB4)
        if encryptedMsg[0:int(i/2)] == encryptedMsg[int(i/2): i]:
            break;
        i+=2;
    return int(i/2);

def isUsingECB(blockSize):
    b4Content = bytes('A'*(blockSize*16), "utf-8")
    encryptedContent = s2_12_AES_128_ECB(b4Content)
    bIsECB = isEBCEcrypted(encryptedContent, blockSize)
    return bIsECB;

def bblockOracle(blockContent, blockSize):
    assert(len(blockContent) == blockSize)
    return s2_12_AES_128_ECB(blockContent)[0:blockSize]



"""
Iput:
    oracle - function that take our-content and return encrypted text (the encrypted text is composed of 'unknown-prefix'-'our-controlled-text'-'unknown-content')
    startBlock - the first block of the 'unknown-content' (the first byte (minus some 'A's) of the content is the first byte of the block)
    startControlledContent - the controlled content which corresponds to the startBlock
    blockOracle - getting block content and returning the encrypted content (according to the real oracle key)
Output:
    the 'unknown-content' decryptrd
"""
def discoverEndOfEncryptedContent(oracle, startBlock, startControlledContent, blockSize, blockOracle):
    discoverUnknownMsg = bytearray();
    encryptedUnknownContent = oracle(startControlledContent)
    
    assert(len(encryptedUnknownContent)%blockSize == 0)
    blockCount = int(len(encryptedUnknownContent)/blockSize)
    
    for blockNumber in range(startBlock, blockCount, 1):#repete for every block
        for byteNumberToFind in range(blockSize):
            
            #step 1 get all possible encryptions (only byteNumberToFind is the variable)
            allPossibleEncryptionsWhileOnlyThatByteChangesDic = {}
            for byte in range(256):
                if blockNumber == startBlock:
                    blockToEncrypt =  b"".join([bytes('A'*(blockSize - (byteNumberToFind + 1)), 'utf-8'), discoverUnknownMsg, bytes([byte])])
                else:
                    blockToEncrypt = b"".join([discoverUnknownMsg[-1 * (blockSize - 1):], bytes([byte])])
                encryptedBlock = blockOracle(blockToEncrypt, blockSize)
                assert(len(blockToEncrypt) == blockSize == len(encryptedBlock))
                allPossibleEncryptionsWhileOnlyThatByteChangesDic[byte] = encryptedBlock
            
            #step 2 get the real encryption (only byteNumberToFind is the variable)
            controlledContent = bytearray(startControlledContent)
            controlledContent.extend(bytes('A'*(blockSize - (byteNumberToFind + 1)), "utf-8"))
            realEncryptionBlockOfbyteNumberToFind = oracle(bytes(controlledContent))[blockNumber*blockSize : (blockNumber + 1)*blockSize]
            
            #step 3 find the byte by matching the encryptions for all the bytes to the real ecryption
            bIsFoundAmatch = False;
            for key, value in allPossibleEncryptionsWhileOnlyThatByteChangesDic.items():
                if realEncryptionBlockOfbyteNumberToFind == value:
                    bIsFoundAmatch = True;
                    discoverUnknownMsg.append(key)
            if bIsFoundAmatch == False:#can be cause of the padding (it changes for different 'controlled-texts' ), it also can be an error
                print('ALERT: bIsFoundAmatch is false, maybe from padding, anyways added /x04 to the unknown msg instead of that byte place')
                discoverUnknownMsg.append(4)
    return discoverUnknownMsg
    
    
    
def s2_12main():
    #encryptedUnknownContent = s2_12_AES_128_ECB(bytes("","utf-8"))
    
    blockSize = discoverBlockSizeOfCipher();
    assert(blockSize == 16)
    bIsECB = isUsingECB(blockSize);
    assert(bIsECB == 1)
    
    unknownDecrypted = discoverEndOfEncryptedContent(s2_12_AES_128_ECB, 0, bytes('','utf-8'), blockSize, bblockOracle)
    print(unknownDecrypted)
    """
    #discovering the unknown msg
    discoverUnknownMsg = bytearray();
    assert(len(encryptedUnknownContent)%blockSize == 0)
    
    for blockNumber in range(int(len(encryptedUnknownContent)/blockSize)):#repete for every block
        for byteNumberToFind in range(blockSize):
            byteNumberBytesShortMsg = bytearray('A'*(blockSize - (byteNumberToFind + 1)), "utf-8")
            
            byteNumberToFindDict = {}
            for byte in range(256):
                guessWork = bytearray()
                if blockNumber == 0:
                    guessWork.extend(byteNumberBytesShortMsg)
                    guessWork.extend(discoverUnknownMsg)
                else:
                    guessWork.extend(discoverUnknownMsg[-1 * (blockSize - 1):])
                assert(len(guessWork) == (blockSize - 1))
                guessWork.append(byte)
                byteNumberToFindDict[byte] = s2_12_AES_128_ECB(guessWork)[0:blockSize]
            
            bytesShortEncrypted = s2_12_AES_128_ECB(byteNumberBytesShortMsg)[blockNumber*blockSize : (blockNumber + 1)*blockSize]
            bIsFoundAmatch = False;
            for key, value in byteNumberToFindDict.items():
                if bytesShortEncrypted == value:
                    bIsFoundAmatch = True;
                    discoverUnknownMsg.append(key)
            assert(bIsFoundAmatch)
    print(discoverUnknownMsg)
    
    
    
    
    
    byteNumberBytesShortMsg = bytearray('A'*(blockSize - (byteNumberToFind + 1)), "utf-8")
            
            byteNumberToFindDict = {}
            for byte in range(256):
                guessWork = bytearray()
                if blockNumber == startBlock:
                    guessWork.extend(byteNumberBytesShortMsg)
                    guessWork.extend(discoverUnknownMsg)
                else:
                    guessWork.extend(discoverUnknownMsg[-1 * (blockSize - 1):])
                assert(len(guessWork) == (blockSize - 1))
                guessWork.append(byte)
                
                #adding startControlledContent before the guessWork
                tmp = bytearray(startControlledContent)
                tmp.extend(guessWork)
                guessWork = bytes(tmp)
                
                byteNumberToFindDict[byte] = oracle(guessWork)[startBlock:startBlock + blockSize]
    """



