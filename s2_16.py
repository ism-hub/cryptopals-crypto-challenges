# -*- coding: utf-8 -*-
"""
CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="
.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.
Stop and think for a second.
Before you implement this attack, answer this question: why does CBC mode have this property?
"""

from s2_11 import generateNRandomeBytes
#from s2_10 import padToBeAMultipleOfN
from s2_10 import AES128CBCCipher
from s1_2 import xor

s2_16KEY = generateNRandomeBytes(16)
s2_16IV = generateNRandomeBytes(16)
ecbCypher = AES128CBCCipher(s2_16KEY, s2_16IV)
prependTxt = "comment1=cooking%20MCs;userdata="
appendText = ";comment2=%20like%20a%20pound%20of%20bacon"

def prependAppendEncrypt(content):
    postHandleContent = content.replace(b';',b':')
    postHandleContent = postHandleContent.replace(b'=',b'+')
    
    res = bytearray(prependTxt, 'utf-8')
    res.extend(postHandleContent)
    res.extend(bytes(appendText,'utf-8'))
    
    return ecbCypher.encrypt(bytes(res))#no need to pad, the cypher do it inside

def isDecryptAdminTrue(encryptedContent):
    decryptedContent = ecbCypher.decrypt(encryptedContent)
    print(decryptedContent)
    splittedContent = decryptedContent.split(b';')
    for scont in splittedContent:
        if scont == b'admin=true':
            return True;
    return False;

"""
we will skip all the games of getting sure that the end of our content takes exactly 2 blocks
(by messing with the controlled content and the resulting encryptoin (we did something similar in s2_14))
and just count the bytes of our preppend

we want to get ';admin=true;' lets look on the text  '?admin?true?' 
'=' is '0b111101' and '?' is '0b111111'  and ';' is '0b111011' so differ in one byte from '?',
all we need to do is to make sure those bytes get flipped in the decryption,
4 is '0b100' and 2 is '0b10'
by knowing how CBC operate we can make sure it will happen

?admin?true?AAAA?admin?true?AAAA
"""
assert(len(prependTxt)==32)
ourContent = b'?admin?true?AAAA?admin?true?AAAA'
assert(len(ourContent)==32)
encryptedRealConted = prependAppendEncrypt(ourContent)
blockToFake = encryptedRealConted[32:32+16]#we need to flip the right bits 

fakeBlock = xor(blockToFake, bytes([4,0,0,0,0,0,2,0,0,0,0,4,0,0,0,0]))
fakeEncryption = b''.join([encryptedRealConted[0:32], fakeBlock, encryptedRealConted[48:]])

assert(isDecryptAdminTrue(fakeEncryption)==True)


