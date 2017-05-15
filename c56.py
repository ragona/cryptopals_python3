
'''
RC4 Single-Byte Biases
RC4 is popular stream cipher notable for its usage in protocols like TLS, WPA, RDP, &c.

It's also susceptible to significant single-byte biases, especially early in the keystream. What does this mean?

Simply: for a given position in the keystream, certain bytes are more (or less) likely to pop up than others. Given enough encryptions of a given plaintext, an attacker can use these biases to recover the entire plaintext.

Now, search online for "On the Security of RC4 in TLS and WPA". This site is your one-stop shop for RC4 information.

Click through to "RC4 biases" on the right.

These are graphs of each single-byte bias (one per page). Notice in particular the monster spikes on z16, z32, z48, etc. (Note: these are one-indexed, so z16 = keystream[15].)

How useful are these biases?

Click through to the research paper and scroll down to the simulation results. (Incidentally, the whole paper is a good read if you have some spare time.) We start out with clear spikes at 2^26 iterations, but our chances for recovering each of the first 256 bytes approaches 1 as we get up towards 2^32.

There are two ways to take advantage of these biases. The first method is really simple:

Gain exhaustive knowledge of the keystream biases.
Encrypt the unknown plaintext 2^30+ times under different keys.
Compare the ciphertext biases against the keystream biases.
Doing this requires deep knowledge of the biases for each byte of the keystream. But it turns out we can do pretty well with just a few useful biases - if we have some control over the plaintext.

How? By using knowledge of a single bias as a peephole into the plaintext.

Decode this secret:

QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F
And call it a cookie. No peeking!

Now use it to build this encryption oracle:

RC4(your-request || cookie, random-key)
Use a fresh 128-bit key on every invocation.

Picture this scenario: you want to steal a user's secure cookie. You can spawn arbitrary requests (from a malicious plugin or somesuch) and monitor network traffic. (Ok, this is unrealistic - the cookie wouldn't be right at the beginning of the request like that - this is just an example!)

You can control the position of the cookie by requesting "/", "/A", "/AA", and so on.

Build bias maps for a couple chosen indices (z16 and z32 are good) and decrypt the cookie.
'''