from srp import SRPClient, SRPSession, SRPServer
from flask import Flask, request
import random
import hashlib

I = 'foo'
P = 'bar'

app = Flask(__name__)
server = SRPServer()
server.add_user(I, P)

handshake_str = 'salt={};B={}'

@app.route("/handshake")
def handshake():
    #parse url
    uid = request.args.get("uid")
    A = int(request.args.get("A"))
    #we don't want to provide a way to easily figure out 
    #which usernames are and are not valid, so this returns
    #a response that looks real but obviously can't be used
    if uid not in server.users:
        return fake_response(), 200
    #get server response
    salt, B = server.start_session(uid, A)
    #return 
    return handshake_str.format(salt, B), 200


@app.route("/validate")
def validate():
    kH = request.args.get("session")
    uid = request.args.get("uid")
    if uid not in server.users:
        return 'nope', 401
    if server.validate_session_key(uid, kH):
        return 'authenticated', 200
    else:
        return 'nope', 401

def fake_response():
    rint = lambda: random.randrange(0, 2<<32)
    salt = rint()
    v = server._v(salt, hashlib.sha1(str(rint()).encode()))
    B = server._B(v, rint())
    return handshake_str.format(salt, B)

def start():
    app.run()

if __name__ == "__main__":
    start()
