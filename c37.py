# from pals import srp_server
from pals.srp import SRPClient, H
import getpass
import requests

#constants
I = input('User:')
P = getpass.getpass()

def kvparse(s):
    fields = s.split(";")
    pairs = [f.split("=") for f in fields]
    return {p[0]:p[1] for p in pairs}

#create client
client = SRPClient(I, P)

#handshake
uid, A = client.start_handshake()
url = 'http://localhost:5000/handshake?uid={}&A={}'.format(uid, A)
res = kvparse(requests.get(url).text)
salt = int(res["salt"])
B = int(res["B"])

#client generates session key and validates
hK = client.generate_session_key(salt, B, H(A, B))
url = 'http://localhost:5000/validate?uid={}&session={}'.format(uid, hK)
res = requests.get(url)

if res.status_code == 200:
    print('======================')
    print('authenticated')
    print('======================')
else:
    print('======================')
    print('rejected')
    print('======================')
#

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