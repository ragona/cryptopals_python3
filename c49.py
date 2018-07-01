from pals import utils
from os import urandom

# secret that exists on both client and server (but is apparently inaccessible to users)
shared_key = b'YELLOW SUBMARINE'


##########
# Server
##########
def server_request(plaintext, client_mac, iv):
    # generate server-side mac
    mac = utils.aes_cbc_mac(plaintext, shared_key, iv, no_pad=True)

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
    iv = b'\x00' * 16
    request = utils.pad(b"from=aaaaa&to=eve&amount=1000000", 16)
    mac = utils.aes_cbc_mac(request, shared_key, iv, no_pad=True)

    # fake request from poor alice
    forged_request = utils.pad(b'from=alice&to=eve&amount=1000000', 16)

    # xor the original iv with the xor of the real and fake request to get the forged iv
    forged_iv = utils.xor(iv, utils.xor(request[:16], forged_request[:16]))

    # validate with server
    server_request(forged_request, mac, forged_iv)


def length_extension_forgery():
    """
    Oh, this is cool! You can reset the state of the CBC-MAC by including a block between two valid
    requests that is the MAC of the first (the last block) with the first block of the second. This
    effectively zeroes out the state and allows you to combine the two.
    ========
    Note: I used a random IV here to prove that this can be done with a random IV as long as the attacker
    knows what it is. It just adds some additional XOR'ing on the zero block; it now includes the IV as
    well as Alice's MAC and Eve's first block.
    """
    iv = urandom(16)

    # this is the legitimate request we're stealing from alice
    alice_request = utils.pad(b'from=alice&tx_list=bob:100;sally:150', 16)
    alice_mac = utils.aes_cbc_mac(alice_request, shared_key, iv, no_pad=True)

    # this is a request that eve is generating with an account she controls
    eve_request = utils.pad(b'from=eve&tx_list=eve:10000;eve:10000', 16)
    eve_mac = utils.aes_cbc_mac(eve_request, shared_key, iv, no_pad=True)

    # this block resets the state of the mac
    zero_block = utils.xor(iv, utils.xor(alice_mac, eve_request[:16]))

    # include the zero block between the two requests
    forged_message = alice_request + zero_block + eve_request[16:]

    # send to the server
    server_request(forged_message, eve_mac, iv)


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