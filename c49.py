from pals import utils


# secret that exists on both client and server (but is apparently inaccessible to users)
shared_key = b'YELLOW SUBMARINE'


##########
# Server
##########
def server_request(plaintext, client_mac, iv):
    # generate server-side mac
    mac = utils.aes_cbc_mac(plaintext, shared_key, iv)

    # verify signature, then execute transaction(s)
    if mac == client_mac:
        print(f'executing {plaintext}')
        return True
    else:
        return False


##########
# Client
##########
def chosen_iv_forgery():
    """
    This is the initial challenge where the client has control of the IV
    """
    # generate "valid" request; imagining here that we can create arbitrary account names ('aaaaa') and also
    # that the client will willingly generate a request for 1M spacebucks (but that the server would reject this
    # or we'd stop it from actually going over the wire).
    iv = b'AAAAAAAAAAAAAAAA'
    request = b"from=aaaaa&to=eve&amount=1000000"
    mac = utils.aes_cbc_mac(request, shared_key, iv)

    # fake request from poor alice
    forged_request = b'from=alice&to=eve&amount=1000000'

    # xor the original iv with the xor of the real and fake request to get the forged iv
    forged_iv = utils.xor(iv, utils.xor(request[:16], forged_request[:16]))

    # validate with server
    server_request(forged_request, mac, forged_iv)


def length_extension_forgery():
    """
    We don't have control over the IV in this one, but we are allowed to submit multiple transactions.
    We're gonna use the MAC from one message as the IV for a length extension attack. Let's imagine
    that we've captured this message from Alice, where she is trying to give some money to people who
    are not Eve.
    """
    iv = b'0' * 16
    request = b'from=alice&tx_list=bob:100;sally:150;joes:20000'
    mac = utils.aes_cbc_mac(request, shared_key, iv)
    extension = b';eve:1000000'

    # fake request by using mac as starting position
    # todo: I'm not sure this was the intended solution. Maybe we should be mangling the request instead?
    forged_mac = utils.aes_cbc_mac(extension, shared_key, mac)

    # note that we need to include the original padding bytes from the first mac
    server_request(request + b'\x01' + extension, forged_mac, iv)


def main():
    chosen_iv_forgery()
    length_extension_forgery()


if __name__ == '__main__':
    main()


"""
CBC-MAC Message Forgery
Let's talk about CBC-MAC.

CBC-MAC is like this:

Take the plaintext P.
Encrypt P under CBC with key K, yielding ciphertext C.
Chuck all of C but the last block C[n].
C[n] is the MAC.
Suppose there's an online banking application, and it carries out user requests by talking to
an API server over the network. Each request looks like this:

message || IV || MAC
The message looks like this:

from=#{from_id}&to=#{to_id}&amount=#{amount}
Now, write an API server and a web frontend for it. (NOTE: No need to get ambitious and write
actual servers and web apps. Totally fine to go lo-fi on this one.) The client and server should
share a secret key K to sign and verify messages.

The API server should accept messages, verify signatures, and carry out each transaction if the
MAC is valid. It's also publicly exposed - the attacker can submit messages freely assuming he
can forge the right MAC.

The web client should allow the attacker to generate valid messages for accounts he controls.
(Feel free to sanitize params if you're feeling anal-retentive.) Assume the attacker is in a
position to capture and inspect messages from the client to the API server.

One thing we haven't discussed is the IV. Assume the client generates a per-message IV and
sends it along with the MAC. That's how CBC works, right?

Wrong.

For messages signed under CBC-MAC, an attacker-controlled IV is a liability. Why? Because it
yields full control over the first block of the message.

Use this fact to generate a message transferring 1M spacebucks from a target victim's account
into your account.

I'll wait. Just let me know when you're done.

... waiting

... waiting

... waiting

All done? Great - I knew you could do it!

Now let's tune up that protocol a little bit.

As we now know, you're supposed to use a fixed IV with CBC-MAC, so let's do that. We'll set ours
at 0 for simplicity. This means the IV comes out of the protocol:

message || MAC
Pretty simple, but we'll also adjust the message. For the purposes of efficiency, the bank wants
to be able to process multiple transactions in a single request. So the message now looks like this:

from=#{from_id}&tx_list=#{transactions}
With the transaction list formatted like:

to:amount(;to:amount)*
There's still a weakness here: the MAC is vulnerable to length extension attacks. How?

Well, the output of CBC-MAC is a valid IV for a new message.

"But we don't control the IV anymore!"

With sufficient mastery of CBC, we can fake it.

Your mission: capture a valid message from your target user. Use length extension to add a transaction
paying the attacker's account 1M spacebucks.

Hint!
This would be a lot easier if you had full control over the first block of your message, huh? Maybe
you can simulate that.

Food for thought: How would you modify the protocol to prevent this?
"""