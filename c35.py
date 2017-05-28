from pals.dh import DHClient, MITM_G_DHClient
g = 2
p = int(('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
         'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
         '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
         '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
         '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
         'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
         'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
         'fffffffffffff'), 16) #just for formatting

alice = DHClient()
bob = DHClient()
#g = p causes session keys to be 0
#g = 1 or g = p - 1 causes session keys to be 1
eve = MITM_G_DHClient(p)

#alice tries to talk to bob, ends up talking to eve
alice.connect(eve, p, g)

#eve mucks with the g value
eve.connect(bob, p, g)

#alice creates a message
msg = alice.encrypt_message(b'banana')

#everyone can read these messages
a = alice.decrypt_message(msg)
b = eve.decrypt_message(msg)
c = alice.decrypt_message(msg)

#messages should match
print(a == b == c)


'''
Implement DH with negotiated groups, and break with 
malicious "g" parameters
A->B
Send "p", "g"
B->A
Send ACK
A->B
Send "A"
B->A
Send "B"
A->B
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
Do the MITM attack again, but play with "g". What happens with:

    g = 1
    g = p
    g = p - 1
Write attacks for each.

When does this ever happen?
Honestly, not that often in real-world systems. If you can 
mess with "g", chances are you can mess with something worse. 
Most systems pre-agree on a static DH group. But the same construction 
exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.
'''