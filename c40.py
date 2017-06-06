from Crypto.Util.number import inverse
from pals.RSA import RSA

msg = b'some secret message'

pub_0 = RSA.generate_keys(1024, 3)[0]
pub_1 = RSA.generate_keys(1024, 3)[0]
pub_2 = RSA.generate_keys(1024, 3)[0]

c_0 = RSA.encrypt(msg, pub_0)
c_1 = RSA.encrypt(msg, pub_1)
c_2 = RSA.encrypt(msg, pub_2)

n_0 = pub_0[1]
n_1 = pub_1[1]
n_2 = pub_2[1]

m_s_0 = n_1 * n_2
m_s_1 = n_0 * n_2
m_s_2 = n_0 * n_1

N_012 = n_0 * n_1 * n_2

result = ((c_0 * m_s_0 * inverse(m_s_0, n_0)) +
          (c_1 * m_s_1 * inverse(m_s_1, n_1)) +
          (c_2 * m_s_2 * inverse(m_s_2, n_2)) % N_012)


#do cube root 

'''
Implement an E=3 RSA Broadcast attack
Assume you're a Javascript programmer. That is, you're using a naive 
handrolled RSA to encrypt without padding.

Assume you can be coerced into encrypting the same plaintext three 
times, under three different public keys. You can; it's happened.

Then an attacker can trivially decrypt your message, by:

Capturing any 3 of the ciphertexts and their corresponding pubkeys
Using the CRT to solve for the number represented by the three 
ciphertexts (which are residues mod their respective pubkeys)
Taking the cube root of the resulting number
The CRT says you can take any number and represent it as the combination 
of a series of residues mod a series of moduli. In the three-residue 
case, you have:

result =
  (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
  (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
  (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
where:

 c_0, c_1, c_2 are the three respective residues mod
 n_0, n_1, n_2

 m_s_n (for n in 0, 1, 2) are the product of the moduli
 EXCEPT n_n --- ie, m_s_1 is n_0 * n_2

 N_012 is the product of all three moduli
To decrypt RSA using a simple cube root, leave off the final modulus 
operation; just take the raw accumulated result and cube-root it.
'''