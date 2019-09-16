# -*- coding: utf-8 -*-
"""
The CBC padding oracle
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
"""

from s2_10 import AES128CBCCipher
from s2_11 import generateNRandomeBytes
import random
import base64
from s2_15 import validPKCS7Padding
from s1_2 import xor

s2_16KEY = generateNRandomeBytes(16)
s2_16IV = generateNRandomeBytes(16)
ecbCypher = AES128CBCCipher(s2_16KEY, s2_16IV)
a10Strings = list(map(base64.b64decode, [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']))




def firstFunction():
    randomeStringFrom10 = a10Strings[random.randint(0,9)]
    return (ecbCypher.encrypt(randomeStringFrom10), s2_16IV)

def secondFunction(encryptedContent):
    enryptedMsg = encryptedContent
    decryptredMsg = ecbCypher.decrypt(enryptedMsg)
    try:
        validPKCS7Padding(decryptredMsg)
    except ValueError:
        return False
    else:
        return True
        
def findFakeBlockForPadOfOne(encryptedBlockToCypher):
    fakeBlock = bytearray(generateNRandomeBytes(len(encryptedBlockToCypher)))
    for byte in range(256):
        fakeBlock[-1] = byte
        if secondFunction(b''.join([fakeBlock, encryptedBlockToCypher])):
            return bytes(fakeBlock);
    

def findCorrectFakeBlockWithPadSizeN(N, fakeBlockWithPadSizeNMinusOne, encryptedBlockToCypher):
    fakeBlockWithPadSizeN = bytearray(fakeBlockWithPadSizeNMinusOne)
    
    for i in range(-(N - 1), 0):
        fakeBlockWithPadSizeN[i] = fakeBlockWithPadSizeNMinusOne[i] ^ (N - 1) ^ N
    
    #search for the byte that will give a correct N bytes padding
    for byte in range(256):
        fakeBlockWithPadSizeN[-N] = byte
        if secondFunction(b''.join([fakeBlockWithPadSizeN, encryptedBlockToCypher])):
            return fakeBlockWithPadSizeN;
    
    assert(False)#not suppose to reach this line

def decryptBlock(hisPreBlock, encryptedBlockToCypher):
    fakeBlock1Pad = findFakeBlockForPadOfOne(encryptedBlockToCypher)
    assert(fakeBlock1Pad != hisPreBlock)
    
    fakeBlockWithPadSizeNMinus1 = fakeBlock1Pad
    for padSize in range(2, len(encryptedBlockToCypher)+1):
        fakeBlockWithPadSizeN = findCorrectFakeBlockWithPadSizeN(padSize, fakeBlockWithPadSizeNMinus1, encryptedBlockToCypher)
        fakeBlockWithPadSizeNMinus1 = fakeBlockWithPadSizeN #for the next loop

    size = len(encryptedBlockToCypher)
    decryptedBlock = xor(xor(fakeBlockWithPadSizeNMinus1, hisPreBlock), bytes([size]*size))
    return decryptedBlock
    
decryptedContent = bytearray()
encryptedContent = firstFunction()[0];
print(len(encryptedContent))

contentLen = len(encryptedContent)
assert(contentLen % 16 == 0)
for bIndx in range(int(contentLen/16)):
    if bIndx == 0:
        prevBlock = s2_16IV
    else:
        prevBlock = encryptedContent[(bIndx - 1)*16:bIndx*16]
    block = encryptedContent[bIndx*16:(bIndx + 1)*16]
    decryptedBlock = decryptBlock(prevBlock, block)
    decryptedContent.extend(decryptedBlock)

print(decryptedContent)
print(a10Strings)














