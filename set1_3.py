# -*- coding: utf-8 -*-
"""
Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

Achievement Unlocked
You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
"""

import base64
from itertools import cycle

def scoreText(text):
    commonCharecters = "etaoinsrhldcumfpgwybvkxjqz "
    rawScore = sum(ch in commonCharecters for ch in text.lower())
    return rawScore/len(text);

def cyclicXor(mainBytes, keyBytes):
    xoredBytes = bytes([(n1 ^ n2) for (n1,n2) in zip(mainBytes, cycle(keyBytes))])
    return xoredBytes;

#try all the 256 possible keys and save/show the n with the best score
#return : [(key, score, text ),...] only the 5 with the bigest score
def cypherOneByteXor(cypheredTextBytes, n):
    results = []; 
    for byte in range(0,256,1):
        key = bytes([byte]);
        uncypheredTextBytes = cyclicXor(cypheredTextBytes, key)
        uncypheredText = uncypheredTextBytes.decode('utf-8', 'replace')
        score = scoreText(uncypheredText)
        results.append((key, score, uncypheredText))
        results.sort(key = lambda tup: tup[1], reverse=True)
        if(len(results) > n):
            results.pop();
    return results
    
def set1_3main():
    textHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    print(cypherOneByteXor(base64.b16decode(textHex.upper()), 5))
    
    