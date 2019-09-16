# -*- coding: utf-8 -*-
"""
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""

from set1_4 import readAllLinesFromFile
import base64

#16 bytes blocks histogram
def blocksHistogram(content, blockSize):#{"the first 'blockSize' bytes" : (number of times it appears, [list of the blocks numbers]), ...}
    result = dict()
    listOfBlocks = [content[blockStartIndex:blockStartIndex+blockSize] for blockStartIndex in range(0, len(content), blockSize)]
    for block, blockNumber in zip(listOfBlocks, range(len(listOfBlocks))):
        blockAndListOfBlockNumbers = result.get(block, (0,[]))
        blockAndListOfBlockNumbers[1].append(blockNumber)
        result[block] = (blockAndListOfBlockNumbers[0]+1, blockAndListOfBlockNumbers[1])
    return result;

#lower the better; scores how much AES-EBC we are
def scoreECBblocksHistogram(blockHistoDict):
    return len(blockHistoDict);
    
def s1_8main():
    fpath = "C:\\Programming\\pythonWorkspaces\\cryptopalsWorkspace\\set1\\8.txt"
    contentHex = readAllLinesFromFile(fpath)
    encryptedTextBytes = [base64.b64decode(contentLineHex) for contentLineHex in contentHex]
    
    allLinesBlockHisto = []
    for encryptedTextLineBytes in encryptedTextBytes:
        allLinesBlockHisto.append(blocksHistogram(encryptedTextLineBytes, 16))
        
    scores = []#[(lineNumber, score), ...]
    for lineBlockHistoLine in range(len(allLinesBlockHisto)):
        lineBlockHisto = allLinesBlockHisto[lineBlockHistoLine]
        score = scoreECBblocksHistogram(lineBlockHisto)
        scores.append((lineBlockHistoLine, score))
    
    scores.sort(key = lambda tup: tup[1])
    print(scores[:5])




