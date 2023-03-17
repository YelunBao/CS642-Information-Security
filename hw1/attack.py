# CS 642 University of Wisconsin
#
# usage: attack.py ciphertext
# Outputs a modified ciphertext and tag

import sys
import os
import Crypto.Cipher.AES
import hashlib

def xor_strings(s,t):
    """xor two strings together"""
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))

def gen_all_hex():
  i = 0
  while i < 16**32:
    yield "{:032X}".format(i)
    i += 1

message = \
"""AMOUNT: $  10.00"""

message_new = \
"""AMOUNT: $  20.00"""

delta = xor_strings(message, message_new)

message_fake = \
"""AMOUNT: $  20.00
Originating Acct Holder: Hugh
Orgininating Acct #82123-09837

I authorized the above amount to be transferred to the account #38108-443280 
held by a Wisc student at the National Bank of the Cayman Islands.
"""

# Grab ciphertext from first argument
ciphertextWithTag = (sys.argv[1]).decode("hex")

if len(ciphertextWithTag) < 16+16+32:
  print("Ciphertext is too short!")
  sys.exit(0)

iv = ciphertextWithTag[:16]
iv_fake = xor_strings(iv, delta)
ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-32]
ciphertext_woiv = ciphertext[16:].encode("hex")
# print(ciphertext_woiv)
tag = ciphertextWithTag[len(ciphertextWithTag)-32:]

'''
s = '2D7F8E92A8E7109258C879F878E12387'
s = s[:32].decode("hex")

cipher = Crypto.Cipher.AES.new(s, Crypto.Cipher.AES.MODE_CBC, IV=iv)
ciphertext_tmp = cipher.encrypt(message).encode("hex")

if ciphertext_tmp == ciphertext_woiv:
  key = s
  print(key.encode("hex"))
else:
  #print(ciphertext_woiv)
  print(ciphertext_tmp)



iv_fake = os.urandom(16)
cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, IV=iv_fake)
ciphertext_fake = cipher.encrypt(message_fake).encode("hex")
'''
tag_fake = hashlib.sha256(message_fake).hexdigest()
#print iv.encode("hex")
#print ciphertext
#print tag
print iv_fake.encode("hex") + ciphertext_woiv + tag_fake

'''
print(key)

# TODO: Modify the input so the transfer amount is more lucrative to the recipient

# TODO: Print the new encrypted message
#print(ciphertext.encode("hex") + tag.encode("hex"))
'''