# -*- coding: utf-8 -*-
"""
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
"""

from s2_11 import generateNRandomeBytes, isEBCEcrypted
from s2_10 import AES128ECBCipher

s2_13KEY = generateNRandomeBytes(16)
ecbCipher = AES128ECBCipher(s2_13KEY)

def pasreURL(urlStr):
    resultDic = {}
    keyValStrs = urlStr.split("&")
    for keyValStr in keyValStrs:
        keyValList = keyValStr.split("=")
        resultDic[keyValList[0]] = keyValList[1]
    return resultDic

def profile_for(emailStr):
    emailPostHandle = emailStr;
    emailPostHandle = emailPostHandle.replace("&", "^")
    emailPostHandle = emailPostHandle.replace("=", "_")
    return "email=" + emailPostHandle + "&uid=10&role=user"
    #return {'email': emailPostHandle, 'uid': 10, 'role': 'user'}

def encryptedUserProfileThatServerGet(emailStr):
    profile = profile_for(emailStr)
    return ecbCipher.encrypt(bytes(profile, "utf-8"))

def whatServerSeeWhenDecrypting(encryptedUserProfile):
    return ecbCipher.decrypt(encryptedUserProfile);

"""
#need to generate encryptedProfile (using only encryptedUserProfileThatServerGet function) 
#that when we decrypt it we will get role=admin profile

we need 3 encrypted blocks and when we concat them and send to the server 
the server will think we sent him a user with admin privilages 

the tree blocks we want:
cypher1 = email=foooo@bar.
cypher2 = com&uid=10&role=
cypher3 = admin\x04\x04\x04\x04\x04\x04

remark - i decided that we pad with \x04 
    i dont think it is a strong assumption cause we can deduce the unknown text
    (similarly to what we did in the previous ex (with little modifications))

"""

#getting cypher1 + 2

cypher12 = encryptedUserProfileThatServerGet("foooo@bar.com")[0:32]
cypher3 = encryptedUserProfileThatServerGet("1111111111admin"+("\x04"*11)+"@.com")[16:32]

adminEncrypted = bytearray(cypher12)
adminEncrypted.extend(cypher3)
print(whatServerSeeWhenDecrypting(bytes(adminEncrypted)))





