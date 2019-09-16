# -*- coding: utf-8 -*-
"""
Byte-at-a-time ECB decryption (Harder)
Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
"""

"""
strategy - we will choose a prefix to our 'attacker-controlled' string in order that the 'target-bytes' 
will start at a new block, meaning - 

|~~~~~~~~~random-prefix~~~~~~~~~~||~~~~~~attacker-controlled-prefix~~~~~~~~||~~~~~~target-bytes~~~~~~~~|
|-----block1-----|....|-----blockn-----||-----blockn1----||-----blockn2----||-----blockn3----|...|-----blockE----|

and from here we just do the same as s2_12 while we use blockn3 as our first block

how to find the blocks:
    * we check if we have any successive blocks when the controlled string is empty
    * we set our controlled-string to 'A'*[blockSize*3] that will guarantee we have successive blocks now
    * we find the first new successive blocks that arent appear in the 'successive blocks when the controlled string is empty' list (that guarantee us the successive blocks are from our controlled-content)
    * we shrink our controlled-string till the block in that position disappears 
    * now (after adding the missing 'A' to the string so we once again get our successive blocks back) we have our picture status
    * from here we do the same as in s2_12

####old reasoning####
how to find the blocks: 
    * keep trying strings of "A" till we will find two cyphered blocks that are the same size
    * there is a problems wich can accure with that -
        * target-bytes can start with "A"'s and we mistakenly think it is part of our prefix
        * the same if random-prefix ends with "A"'s
            - in both of those cases its not really matter we still can find target-bytes (without some "A"'s in the beggining)
        * we will get two similar encrypted blocks but they wont be of our prefix - i.e- random-prefix ends with "ABC" and our prefix is "AAAAA" and target bytes start with "ABCAAAAA"
            - to avoid it our prefix will start with a string that take two-block-size 
             (and we guaranteed that one block in the encryption will be encryption of block of "A"'s)
             then (while we enlarge our prefix) we make sure our two same encryptedblocks are next to each other
            -ffs - we also need to make sure to ignore same encrypted blocks that appear in 'target-bytes'
             and 'random-prefix' 
         (we left with the need to prove that all of this is enough or correct)
"""

from s1_8 import blocksHistogram
from s2_11 import generateNRandomeBytes
import random
import base64
from s2_10 import AES128ECBCipher
from s2_12 import discoverEndOfEncryptedContent

s2_14KEY = generateNRandomeBytes(16)
s2_14PREFIX = generateNRandomeBytes(random.randint(0,100))


def s2_14_AES_128_ECB(controlledContent):
    unknownContent = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    
    contentToEncrypt = bytearray(s2_14PREFIX)
    contentToEncrypt.extend(controlledContent)
    contentToEncrypt.extend(unknownContent)
    contentToEncrypt = bytes(contentToEncrypt)
    
    cbeCipher = AES128ECBCipher(s2_14KEY)
    encryptedContent = cbeCipher.encrypt(contentToEncrypt)
    return encryptedContent;

#finding two successive blocks which are the same,
#returning the forst block and its location [(block, block number), ...] 
#remark the ret list is sorted by block number (the block position)
def getListOfSuccessiveBlocks(content, blockSize):
    histoWithoutControlledContent = blocksHistogram(content, blockSize)
    res = []#[(block, block number), ...]
    for encryptedBlock, numOfAppearancesAndLocations in histoWithoutControlledContent.items():
        numOfAppearances = numOfAppearancesAndLocations[0]
        blockNumbers = numOfAppearancesAndLocations[1]
        if numOfAppearances > 1:
            blockNumbers.sort()
            for i in range(len(blockNumbers) - 1):#checking if we have two successive blocks
                if(blockNumbers[i] + 1 == blockNumbers[i+1]):#if successive
                    res.append((encryptedBlock, blockNumbers[i]))
    res.sort(key = lambda tup: tup[1])
    return res;


#if the successive block are the same and in the same position as in the notToBeList we ignore them
#(both successiveBlocks and notToBeList are sorted by the block position
def firstSuccessiveBlocksWhichNotInList(successiveBlocks, notToBeList):
    for successiveBlock in successiveBlocks:
        flagIsGoodSuccessiveBlock = True;
        for evilSuccessiveBlock in notToBeList:
            if (successiveBlock[0] == evilSuccessiveBlock[0]) and (successiveBlock[1] == evilSuccessiveBlock[1]):
                flagIsGoodSuccessiveBlock == False;
                break;
        if flagIsGoodSuccessiveBlock:
            return successiveBlock;
    return [];#we didn't find any good ones

class BlockOracle:
    def __init__(self, controlledContentPrefix, firstSuccessiveBlock):
        self.controlledContentPrefix = controlledContentPrefix
        self.firstSuccessiveBlock = firstSuccessiveBlock

    def blockOracle(self, content, blockSize):
        assert(len(content) == blockSize)
        return s2_14_AES_128_ECB(b"".join([self.controlledContentPrefix, content]))[(firstSuccessiveBlock[1]+2)*blockSize:(firstSuccessiveBlock[1]+3)*blockSize]



successiveBlocksNoControlledContent = getListOfSuccessiveBlocks(s2_14_AES_128_ECB(bytes()), 16)
print(successiveBlocksNoControlledContent)

conrolledContent = bytes('A'*(16*3), 'utf-8')#that will guarantee we get a successive pair of blocks
print(conrolledContent)
encryptedContent = s2_14_AES_128_ECB(conrolledContent)
successiveBlocks = getListOfSuccessiveBlocks(encryptedContent, 16)
firstSuccessiveBlock = firstSuccessiveBlocksWhichNotInList(successiveBlocks, successiveBlocksNoControlledContent)
assert(firstSuccessiveBlock != [])

#smaller and smaller till our firstSuccessiveBlock disappears
currentFirstSuccessiveBlock = firstSuccessiveBlock;
while currentFirstSuccessiveBlock == firstSuccessiveBlock:
    conrolledContent = conrolledContent[:-1]
    encryptedContent = s2_14_AES_128_ECB(conrolledContent)
    successiveBlocks = getListOfSuccessiveBlocks(encryptedContent, 16)
    currentFirstSuccessiveBlock = firstSuccessiveBlocksWhichNotInList(successiveBlocks, successiveBlocksNoControlledContent)
controlledContentPrefix = b"".join([conrolledContent, bytes([conrolledContent[0]])])
print(controlledContentPrefix)

#now we have the drawing and we can do s2_12
bOracle = BlockOracle(controlledContentPrefix, firstSuccessiveBlock)
unknownDecrypted = discoverEndOfEncryptedContent(s2_14_AES_128_ECB, firstSuccessiveBlock[1]+2, controlledContentPrefix, 16, bOracle.blockOracle)
print(unknownDecrypted)







