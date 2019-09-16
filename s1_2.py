# -*- coding: utf-8 -*-
"""
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
"""

import base64

#xor two things that which have - len(content1) == len(content2)
def xor(content1, content2):
    if len(content1) != len(content2):
        raise ValueError('the two contents need to be the same size')
    xoredBytes = bytes([(n1 ^ n2) for (n1,n2) in zip(content1, content2)])
    return xoredBytes

def s1_2main():
    num1Hex = "1c0111001f010100061a024b53535009181c"
    num2Hex = "686974207468652062756c6c277320657965"
    numBytes1 = base64.b16decode(num1Hex.upper());
    numBytes2 = base64.b16decode(num2Hex.upper());
        
    xoredBytes = xor(numBytes1, numBytes2);
    numXorHex = base64.b16encode(xoredBytes).decode('utf-8')
    assert(numXorHex == "746865206b696420646f6e277420706c6179".upper())
    print(numXorHex)
