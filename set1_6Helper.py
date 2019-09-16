# -*- coding: utf-8 -*-
"""
Here I will cypher some text and check if the algorithm in set1_6 can solve it

they key - "Yellow"
the text - 

"Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
is 37. Make sure your code agrees before you proceed.
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances."

"""

from set1_3 import cyclicXor,cypherOneByteXor
from set1_4 import readAllLinesFromFile
import base64

def HamingDist(bytes1, bytes2):
    return sum([bin(b1^b2).count("1") for (b1,b2) in zip(bytes1,bytes2)])

"""
example - 
    input- listIn=[1,2,3,4,5,6,7,8]; chunkSize=3
    output- [[1,2,3],[4,5,6],[7,8]]
"""
def getListOfChunks(listIn, chunkSize):
    retList=[listIn[chunkStartIndex:chunkStartIndex+chunkSize] for chunkStartIndex in list(range(0,len(listIn),chunkSize))];
    return retList; 

#calculate the score for KeySize (getting avarage of haming dist between pairs)
def calculateKeySizeScore(textBytes, KeySize):
    normalizedHamDistSum = 0.0;
    counter=0;
    chunks = getListOfChunks(textBytes, KeySize*2)
    for chunk in chunks:
        if len(chunk) == KeySize*2:
            chunk1AndChunk2 = getListOfChunks(chunk, KeySize)
            normalizedHamDistSum += HamingDist(chunk1AndChunk2[0], chunk1AndChunk2[1])/(KeySize*8)
            counter+=1;
    return normalizedHamDistSum/counter;

#return the n best keySizes
def getBestKeySize(encryptedTextBytest, n):
    keysDist = []#[(distance, keySize), ...]
    for KEYSIZE in range(2,41,1):
        score = calculateKeySizeScore(encryptedTextBytest, KEYSIZE)
        keysDist.append((score, KEYSIZE))
    keysDist.sort(key = lambda tup: tup[0])
    return keysDist[:n]

"""
Transpose
example - 
    Input  - listOfLists = [[1,2,3],[4,5,6],[7,8,9],[10,11]]
    Output - [[1,4,7,10],[2,5,8,11],[3,6,9]]
"""
def getListOfColumns(listOfLists):#Transpose
    #initialize
    columnsList = []
    for row in listOfLists:
        for colIndex in range(len(row)):
            if len(columnsList) < colIndex + 1:#starting a new column
                columnsList.append([])
            columnsList[colIndex].append(row[colIndex])
    return columnsList;

def set1_6HelperMain():
    #key = "haibaigai"
    #print(len(key))
    #text = "Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.\nWrite a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:\nis 37. Make sure your code agrees before you proceed.\nFor each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.\nThe KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances."
    
    #encrypting the text and then b64 represent it 
    #encryptedTextBytes = cyclicXor(bytes(text,'utf-8'), bytes(key,'utf-8'))
    fpath = "C:\\Programming\\pythonWorkspaces\\cryptopalsWorkspace\\set1\\6.txt"
    content64 = readAllLinesFromFile(fpath)
    content64OneLine = ''.join(content64)
    encryptedTextBytes = base64.b64decode(content64OneLine)

    
    #encryptedTextB64 = base64.b64encode(encryptedTextBytes)
    #print(encryptedTextB64)
    
    #cyphering the text by the alg in the question
    #encryptedTextBytest = base64.b64decode(encryptedTextB64)
    bestSize = getBestKeySize(encryptedTextBytes, 7)[0][1]
    chunksOfBestSize = getListOfChunks(encryptedTextBytes, bestSize)
    oneByteXorLettersList = getListOfColumns(chunksOfBestSize)
    #cypher the key by using 1ByteXor cypher
    keyletters=[]
    for oneByteXorLetters in oneByteXorLettersList:
        keyletters.append(cypherOneByteXor(oneByteXorLetters,1))
    cypheredKeyBytesList = [res[0][0] for res in keyletters]
    cypheredKeyBytes = bytearray();
    for keyByte in cypheredKeyBytesList:
        cypheredKeyBytes.append(keyByte[0])
    print('')
    print(cypheredKeyBytes)
    cypheredText = cyclicXor(encryptedTextBytes, cypheredKeyBytes)
    print('')
    print(cypheredText)


