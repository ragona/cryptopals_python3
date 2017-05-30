from pals.srp import SRPClient, SRPSession, SRPServer
from flask import Flask, request

I = 'me@here.com'
P = 'p@$$W0RD'

app = Flask(__name__)
server = SRPServer()
server.add_user(I, P)

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

@app.route("/handshake")
def handshake():
    #parse url
    uid = request.args.get("uid")
    A = int(request.args.get("A"))
    #make sure user exists
    if uid not in server.users:
        return 'nope\n', 404
    #get server response
    salt, B = server.handshake_response(uid, A)
    #return 
    return 'salt={};B={}'.format(salt, B), 200


@app.route("/validate")
def validate():
    #client session 
    kH = request.args.get("session")
    #session key params
    uid = request.args.get("uid")
    A = int(request.args.get("A"))
    u = int(request.args.get("u"))
    #generate key
    server.generate_session_key(uid, A, u)
    #validate
    if server.validate_session_key(uid, kH):
        return 'authenticated', 200
    else 
        return 'nope', 401

def start():
    app.run()

