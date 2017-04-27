

'''
Byte-at-a-time ECB decryption (Harder)
Take your oracle function from #12. Now generate 
a random count of random bytes and prepend this 
string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
'''