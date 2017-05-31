# from pals import srp_server
from pals.srp import SRPClient, H
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
#get data from user
zero_key = True if input("zero key? (y/n):") == 'y' else False
N_key = True if input("N key? (y/n):") == 'y' else False
Nx2_key = True if input("N*2 key? (y/n):") == 'y' else False
I = input('User: ')
P = getpass.getpass()

def kvparse(s):
    fields = s.split(";")
    pairs = [f.split("=") for f in fields]
    return {p[0]:p[1] for p in pairs}

#create client
client = SRPClient(I, P)


#handshake out
if zero_key:
    print("ZERO KEY")
    uid, A = client.start_handshake(0)
elif N_key:
    print("N KEY")
    uid, A = client.start_handshake(N)
elif Nx2_key:
    print("N*2 KEY")
    uid, A = client.start_handshake(N*2)
else:
    print("NORMAL KEY")
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

#client generates session key and validates
S, K, hK = client.generate_session_key(salt, B, H(A, B))
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
    print('======================')
    print('200: authorized')
    print('======================')
elif res.status_code == 401:
    print('======================')
    print('401: not authorized')
    print('======================')
else:
    print('======================')
    print(res.status_code)
    print('======================')


'''
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
        valid = self.server.validate_session_key(self.uid, kH)
        if not valid:
            raise Exception('invalid session')
'''

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