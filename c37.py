'''
This is the client for the challenge. It has a bunch of 
debug logging to make it easier to see what the various 
parameters are. The server is in pals/srp_server.py and
that file must be running in order for the client to 
connect to it. The server has a single user in it with
the username 'foo' password 'bar'. 
'''

# from pals import srp_server
from pals.srp import SRPClient, H, hash, hmac_sha256
import getpass
import requests

#constants
N = int(('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
         'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
         '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
         '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
         '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
         'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
         'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
         'fffffffffffff'), 16) #just for formatting

#helper method for parsing server key/value repsonse
def kvparse(s):
    fields = s.split(";")
    pairs = [f.split("=") for f in fields]
    return {p[0]:p[1] for p in pairs}

#===================
# user input 
#===================

#series of flags to send bad A values
A_override = int(input("A override? (0=normal,1=zero,2=N,3=N*2): ".strip()))

#username + password
I = input('User: ')
P = getpass.getpass()

#create client
client = SRPClient(I, P)

#handshake out
if A_override == 1:
    uid, A = client.start_handshake(0)
elif A_override == 2:
    uid, A = client.start_handshake(N)
elif A_override == 3:
    uid, A = client.start_handshake(N*2)
else:
    uid, A = client.start_handshake()

print("=====================")
print("1a. CLIENT HANDSHAKE")
print("=====================")
print("N:", N)
print("uid:", uid)
print("A:", A)

#send request
url = 'http://localhost:5000/handshake?uid={}&A={}'.format(uid, A)
res = kvparse(requests.get(url).text)

#response
salt = int(res["salt"])
B = int(res["B"])
print("=====================")
print("1b. SERVER RESPONSE")
print("=====================")
print("salt:", salt)
print("B:", B)

#client generates session key
S, K, hK = client.generate_session_key(salt, B, H(A, B))

#if we're tampering with the A value, this causes the S 
#values on the server to come out to zero, so we can 
#generate a hash that matches even without the password
if A_override != 0:
    hK = hmac_sha256(salt, hash(0))

print("=====================")
print("2a. CLIENT SESSION")
print("=====================")
print("S:", S)
print("K:", K)
print("hK:", hK)

#send request
url = 'http://localhost:5000/validate?uid={}&session={}'.format(uid, hK)
res = requests.get(url)

#check status
print("=====================")
print("2b. SERVER RESPONSE")
if res.status_code == 200:
    print("=====================")
    print('200: authorized')
    print('=====================')
elif res.status_code == 401:
    print('=====================')
    print('401: not authorized')
    print('=====================')
else:
    print('=====================')
    print(res.status_code)
    print('=====================')


'''
Break SRP with a zero key
Get your SRP working in an actual client-server setting. 
"Log in" with a valid password using the protocol.

Now log in without your password by having the client 
send 0 as its "A" value. What does this to the "S" 
value that both sides compute?

Now log in without your password by having the client 
send N, N*2, &c.

Cryptanalytic MVP award
Trevor Perrin and Nate Lawson taught us this attack 
7 years ago. It is excellent. Attacks on DH are tricky 
to "operationalize". But this attack uses the same concepts, 
and results in auth bypass. Almost every implementation of 
SRP we've ever seen has this flaw; if you see a new one, 
go look for this bug.
'''