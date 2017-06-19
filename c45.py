from hashlib import sha1
from pals.DSA import DSA, H
from Crypto.Util.number import inverse

msg_a = b'Hello, world'
msg_b = b'Goodbye, world'

def main():
    #default params
    p,q,g,y = DSA.generate_user_key_pair()[0]

    #submitting 0 as g causes r to be 0 -- but
    #correct DSA implementations should choke on
    #trying to generate keys in this case
    pub, pri = DSA.generate_user_key_pair(p,q,0)
    zero_g_sig_a = DSA.sign(msg_a, pri, True)

    #submitting p + 1 causes you to be able to sign
    #any message and have it validate (!!!)  
    pub, pri = DSA.generate_user_key_pair(p,q,p+1)
    p,q,g,y = pub
    z = 2
    r = (pow(y,z,p)) % q #wtf is z? 
    s = (r * inverse(z, q)) % q

    #verify
    assert(DSA.verify(msg_a, (r,s), pub))
    assert(DSA.verify(msg_b, (r,s), pub))

    #
    print('success')


if __name__ == '__main__':
    main()
'''
DSA parameter tampering
Take your DSA code from the previous exercise. Imagine it as 
part of an algorithm in which the client was allowed to propose 
domain parameters (the p and q moduli, and the g generator).

This would be bad, because attackers could trick victims into 
accepting bad parameters. Vaudenay gave two examples of bad 
generator parameters: generators that were 0 mod p, and generators 
that were 1 mod p.

Use the parameters from the previous exercise, but substitute 
0 for "g". Generate a signature. You will notice something bad. 
Verify the signature. Now verify any other signature, for any 
other string.

Now, try (p+1) as "g". With this "g", you can generate a magic 
signature s, r for any DSA public key that will validate against 
any string. For arbitrary z:

  r = ((y**z) % p) % q

        r
  s =  --- % q
        z
Sign "Hello, world". And "Goodbye, world".
'''