'''
See /ref/bleichenbacher_padding.pdf for the whitepaper 
'''

from pals.RSA import RSA, pkcs_115_pad
from pals.utils import bytes_to_int, int_to_bytes

#==============
# SERVER
#==============

class RSA_padding_oracle:

    def __init__(self, private_key):
        self.e, self.n = self.private_key = private_key

    def oracle(self, ciphertext): 
        plain = b'\x00' + RSA.decrypt(ciphertext, self.private_key)
        return plain[:2] == b'\x00\x02' and len(plain) * 8 == self.n.bit_length()

#==============
# CLIENT
#==============

def ceil(a, b):
    return (a + b - 1) // b

def bleichenbacher(c, public_key, oracle):
    '''
    setup
    '''
    e, n = public_key
    k = n.bit_length() // 8
    B = 2**(8*(k-2))
    M = [(2*B, 3*B-1)]

    print(M)
    '''
    step 1.0: blinding (why is it called blinding?)
    oh I think it's called blinding because you're just blindly looking through 
    numbers until you find one that is pkcs conforming. if you start with a known 
    good 'c' then I think you can just set c_0 to the initial c that you pass in 
    '''

    c_0 = c

    '''
    step 2.0: search for pkcs conforming messages
    I was initially planning to do this step by step, but I don't think the steps 
    are actually totally linear. For example, after step 1 you will only have one
    tuple in M. You'll go to 2.a, which will find the first pkcs conforming s, but
    will not add anything to M, so you'll then hop down to step 2.c. Wait... when
    the hell do you actually add anything to M? I don't understand when 2.b would
    be triggered. 
    '''

    a, b = M[0]
    while True:

        '''
        step 2.a: starting the search
        we're finding the first s value here, beginning at n/3B. we use ceil because 
        otherwise we have to do weird floating point math, and we don't want the floor 
        of n//3B.
        '''
        i = 1
        if i == 1:
            s = ceil(n, B*3)
            while True:
                c = c_0 * (pow(s, e, n)) % n
                if oracle(c):
                    break
                s += 1

        print(s)
        i+= 1
        break
        #step 2.b: searching with more than one interval left
        #step 2.c: searching with one interval left
        #step 3.0: narrowing the set of solutions
        #step 4.0: computing the solution 

#==============
# MAIN
#==============

def main(): 
    pub, pri = RSA.generate_keys(256)
    o = RSA_padding_oracle(pri)
    m = pkcs_115_pad(b'kick it, CC', o.n, 2)
    c = RSA.encrypt(m, pub)

    bleichenbacher(c, pub, o.oracle)

if __name__ == '__main__':
    main()


'''
Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
Degree of difficulty: moderate
These next two challenges are the hardest in the entire set.
Let us Google this for you: "Chosen ciphertext attacks against 
protocols based on the RSA encryption standard"

This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps 
versions on the first search page.

Read the paper. It describes a padding oracle attack on PKCS#1v1.5. 
The attack is similar in spirit to the CBC padding oracle you built 
earlier; it's an "adaptive chosen ciphertext attack", which means you 
start with a valid ciphertext and repeatedly corrupt it, bouncing the 
adulterated ciphertexts off the target to learn things about the original.

This is a common flaw even in modern cryptosystems that use RSA.

It's also the most fun you can have building a crypto attack. It involves 
9th grade math, but also has you implementing an algorithm that is complex 
on par with finding a minimum cost spanning tree.

The setup:

Build an oracle function, just like you did in the last exercise, but have 
it check for plaintext[0] == 0 and plaintext[1] == 2.
Generate a 256 bit keypair (that is, p and q will each be 128 bit primes), [n, e, d].
Plug d and n into your oracle function.
PKCS1.5-pad a short message, like "kick it, CC", and call it "m". Encrypt to to get "c".
Decrypt "c" using your padding oracle.
For this challenge, we've used an untenably small RSA modulus (you could f
actor this keypair instantly). That's because this exercise targets a specific 
step in the Bleichenbacher paper --- Step 2c, which implements a fast, nearly 
O(log n) search for the plaintext.

Things you want to keep in mind as you read the paper:

RSA ciphertexts are just numbers.
RSA is "homomorphic" with respect to multiplication, which means you can 
multiply c * RSA(2) to get a c' that will decrypt to plaintext * 2. This is 
mindbending but easy to see if you play with it in code --- try multiplying 
ciphertexts with the RSA encryptions of numbers so you know you grok it.
What you need to grok for this challenge is that Bleichenbacher uses multiplication 
on ciphertexts the way the CBC oracle uses XORs of random blocks.
A PKCS#1v1.5 conformant plaintext, one that starts with 00:02, must be a number 
between 02:00:00...00 and 02:FF:FF..FF --- in other words, 2B and 3B-1, where B 
is the bit size of the modulus minus the first 16 bits. When you see 2B and 3B, 
that's the idea the paper is playing with.
To decrypt "c", you'll need Step 2a from the paper (the search for the first "s" 
that, when encrypted and multiplied with the ciphertext, produces a conformant 
plaintext), Step 2c, the fast O(log n) search, and Step 3.

Your Step 3 code is probably not going to need to handle multiple ranges.

We recommend you just use the raw math from paper (check, check, double check your 
translation to code) and not spend too much time trying to grok how the math works.
'''