# -*- coding: utf-8 -*-
"""
Implement PKCS#7 padding
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
"""

""" psck#7 style
examples - 
    Input: block="YELLOW SUBMARINE", wantedSize=20
    Output: "YELLOW SUBMARINE\x04\x04\x04\x04"
    
    Input: block="YELLOW SUBMARIN", wantedSize=20
    Output: "YELLOW SUBMARIN\x05\x05\x05\x05\x05"
    
    Throws: exception if len(block) > wantedSize
"""

def padToLen(block, wantedSize):
    if(len(block) > wantedSize):
        raise ValueError('block size is too big for padding to the wanted block size')
    sizeToPad = wantedSize - len(block)
    res = bytearray(block)
    res.extend([sizeToPad]*sizeToPad)
    return res
    