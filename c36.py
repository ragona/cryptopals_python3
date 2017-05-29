import hashlib
import hmac
import random
from pals.utils import modexp


g = 2
k = 3
N = int(('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
         'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
         '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
         '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
         '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
         'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
         'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
         'fffffffffffff'), 16) #just for formatting

def H(*args): 
    a = ':'.join(str(a) for a in args)
    return int(hash(a), 16)

def hash(s):
    return hashlib.sha256(str(s).encode('utf-8')).hexdigest()

def hmac_sha256(key, msg):
    return hmac.new(str(key).encode(), str(msg).encode(), digestmod=hashlib.sha256).hexdigest()

class SRPSession:
    def __init__(self, client, server):
        self.client = client
        self.server = server

    def handshake(self):
        #get user id and client ephemeral key
        self.uid, self.A = self.client.start_handshake()
        #get salt and server ephemeral key
        self.salt, self.B = self.server.handshake_response(self.uid, self.A)
        #generate scrambling parameter
        self.u = H(self.A, self.B)

    def validate(self):
        #both generate session keys
        self.client.generate_session_key(self.salt, self.B, self.u)
        self.server.generate_session_key(self.uid, self.A, self.u)
        #client sends hash to be verified 
        kH = self.client.hashed_session()
        #server validates
        valid = server.validate_session_key(self.uid, kH)
        if not valid:
            raise Exception('invalid session')

class SRPServer:

    class User:
        def __init__(self, salt, v):
            self.salt, self.v = salt, v

        def start_session(self):
            self.b = random.randrange(0, 2<<32) 

    def __init__(self):
        self.users = {}

    def add_user(self, uid, password):
        salt = random.randrange(0, 2<<32)
        x = H(salt, password)
        v = pow(g, x, N)
        self.users[uid] = self.User(salt, v)

    def handshake_response(self, uid, a):
        user = self.users[uid]
        user.start_session()
        self.B = (k * user.v + pow(g, user.b, N)) % N
        return user.salt, self.B

    def generate_session_key(self, uid, A, u):
        user = self.users[uid]
        s1 = pow(user.v, u, N)
        S = pow(A * pow(user.v, u, N), user.b, N) 
        self.K = hash(S)
        return self.K

    def validate_session_key(self, uid, K):
        user = self.users[uid]
        return K == hmac_sha256(user.salt, self.K)


class SRPClient:    

    def __init__(self, uid, password):
        self.uid = uid
        self.password = password

    def start_handshake(self):
        self.a = random.randrange(0, 2<<32)
        self.A = pow(g, self.a, N)
        return self.uid, self.A

    def generate_session_key(self, salt, B, u):
        self.salt = salt
        x = H(salt, self.password)
        S = pow(B - k * pow(g, x, N), self.a + u * x, N)
        self.K = hash(S)

    def hashed_session(self):
        return hmac_sha256(self.salt, self.K)

I = 'me@here.com'
P = 'p@$$W0RD'

#create client and server
server = SRPServer()
client = SRPClient(I, P)
#create a user on the server
server.add_user(I, P)
#create a session
session = SRPSession(client, server)
#do the initial handshake 
session.handshake()
#validate the session
session.validate()


'''
SIMPLIFIED: 
0. create user on server
1. start session - public ephemeral key exchange 
2. validate session key

Implement Secure Remote Password (SRP)
To understand SRP, look at how you generate an AES key from DH; 
now, just observe you can do the "opposite" operation an generate 
a numeric parameter from a hash. Then:

Replace A and B with C and S (client & server)

C & S
INITIAL CONSTANTS
Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
GENERATE SALT AND VALIDATOR FOR USER 
S
Generate salt as random integer
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate v=g**x % N
Save everything but x, xH
CLIENT SEND EMAIL AND EPHEMERAL KEY
C->S
Send I, A=g**a % N (a la Diffie Hellman)
SERVER SEND SALT AND EPHEMERAL KEY
S->C
Send salt, B=kv + g**b % N
BOTH GENERATE SCRAMBLING PARAMETER
S, C
Compute string uH = SHA256(A|B), u = integer of uH
CLIENT GENERATES SESSION KEY
C
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate S = (B - k * g**x)**(a + u * x) % N
Generate K = SHA256(S)
SERVER GENERATES SESSION KEY
S
Generate S = (A * v**u) ** b % N
Generate K = SHA256(S)
CLIENT SENDS PROOF OF SESSION KEY
C->S
Send HMAC-SHA256(K, salt)
SERVER VALIDATES SESSION KEY
S->C
Send "OK" if HMAC-SHA256(K, salt) validates
You're going to want to do this at a REPL of some sort; it may 
take a couple tries.

It doesn't matter how you go from integer to string or string to 
integer (where things are going in or out of SHA256) as long as 
you do it consistently. I tested by using the ASCII decimal 
representation of integers as input to SHA256, and by converting 
the hexdigest to an integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password 
into the public keys. The server also takes an extra step to avoid 
storing an easily crackable password-equivalent.
'''

'''
Carol       Steve
1.      C -->   (lookup s, v)
2.  x = H(s, P) <-- s   
3.  A = g^a A -->   
4.      <-- B, u    B = v + g^b
5.  S = (B - g^x)^(a + ux)      S = (A · v^u)^b
6.  K = H(S)        K = H(S)
7.  M[1] = H(A, B, K)   M[1] -->    (verify M[1])
8.  (verify M[2])   <-- M[2]    M[2] = H(A, M[1], K)
Table 4: The Secure Remote Password Protocol

n   A large prime number. All computations are performed modulo n.
g   A primitive root modulo n (often called a generator)
s   A random string used as the user's salt
P   The user's password
x   A private key derived from the password and salt
v   The host's password verifier
u   Random scrambling parameter, publicly revealed
a,b Ephemeral private keys, generated randomly and not publicly revealed
A,B Corresponding public keys
H() One-way hash function
m,n The two quantities (strings) m and n concatenated
K   Session key

'''
