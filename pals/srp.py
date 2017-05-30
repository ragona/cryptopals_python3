import hashlib
import hmac
import random
import requests

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
        valid = self.server.validate_session_key(self.uid, kH)
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

    def handshake_response(self, uid, A):
        user = self.users[uid]
        user.start_session()
        self.B = (k * user.v + pow(g, user.b, N)) % N
        self.u = H(A, self.B)
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