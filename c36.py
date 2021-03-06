from pals.srp import SRPClient, SRPServer, SRPSession

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
