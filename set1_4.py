# -*- coding: utf-8 -*-
"""
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
"""

from set1_3 import cypherOneByteXor
import base64

def readAllLinesFromFile(fpath):
    with open(fpath) as f:
        content = f.readlines()
    # you may also want to remove whitespace characters like `\n` at the end of each line
    content = [x.strip() for x in content]
    return content;

#we will find the best 3 keyes for every row then look at the 10 best matches (from the total of 60*3 lines)
def set1_4main():
    fpath = "C:\\Programming\\pythonWorkspaces\\cryptopalsWorkspace\\set1\\4.txt"
    content = readAllLinesFromFile(fpath)
    
    allResults = [];
    for textHex in content:
        oneResult = cypherOneByteXor(base64.b16decode(textHex.upper()), 3)
        allResults.extend(oneResult)
    allResults.sort(key = lambda tup: tup[1], reverse=True)
    print(allResults[0:10])


