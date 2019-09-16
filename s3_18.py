# -*- coding: utf-8 -*-
"""
Implement CTR, the stream cipher mode
The string:

L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)
CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
... for the next 16 bytes:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
... and then:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.

This is the only block cipher mode that matters in good code.
Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers, because most of what we want to encrypt is better described as a stream than as a sequence of blocks. Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt" transforms. Constructions like CTR are what he was talking about.
"""

from s2_10 import AES128ECBCipher
import math
from s2_11 import generateNRandomeBytes
import base64

def xorNotSameSize(one, two):
    return  bytes([ OneTwoPair[0]^OneTwoPair[1] for OneTwoPair in zip(one, two)]);

class AES128CTRCipher:
    
    def __init__(self, key):
        assert(len(key)==16)
        self.key = key;
        self.aES128ECB = AES128ECBCipher(key);
        
        
    def generateKeyStream(self, size, nonce):
        #how many blocks we need to cypher
        numOfBlocks = math.ceil(size/16)
        #generate the blocks to to EBC encrypt
        blocksToEncrypt = [];
        for bIndx in range(numOfBlocks):
            counter = (bIndx).to_bytes(8, byteorder='little')
            blockToEncrypt = b''.join([nonce, counter])
            assert(len(blockToEncrypt) == 16)
            blocksToEncrypt.append(blockToEncrypt)
        keyStream = bytearray();
        for blockToEncrypt in blocksToEncrypt:
            keyStream.extend(self.aES128ECB.encrypt(blockToEncrypt))
        return bytes(keyStream);
    
    def encrypt(self, content, nonce):
        assert(len(nonce) == 8)
        keyStream = self.generateKeyStream(len(content), nonce)
        
        #encrypt the content
        encryptedContent = xorNotSameSize(keyStream, content)
        return encryptedContent;
        
    def decrypt(self, encryptedContent, nonce):
        keyStream = self.generateKeyStream(len(encryptedContent), nonce)
        decryptedContent = xorNotSameSize(keyStream, encryptedContent)
        return decryptedContent;

def s3_18main():
    key = b'YELLOW SUBMARINE'
    nonce = (0).to_bytes(8, byteorder='little')
    CRTCipher = AES128CTRCipher(key)
    
    encryptedContent = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    decryptedContent = CRTCipher.decrypt(encryptedContent, nonce)
    print(decryptedContent)





