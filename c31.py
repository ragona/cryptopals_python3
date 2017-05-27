import requests, math

def test(file, signature):
    response = requests.get('http://localhost:5000/verify?file={}&signature={}'.format(file, signature))
    if response.status_code == 200:
        return True
    else:
        return response.elapsed.microseconds

#retry count tries multiple times and gives an
#average to eliminate random network jitter
def crack_hmac(input, retry_count):
    tststr = ''
    hexstr = '0123456789abcdef'
    while True:
        slowest_chr = ''
        slowest_int = 0
        for i in range(16):
            avg = 0
            for j in range(retry_count):
                result = test(input, tststr + hexstr[i])
                if result is True:
                    return tststr + hexstr[i]
                avg += result
            avg /= retry_count
            if avg > slowest_int:
                slowest_chr = hexstr[i]
                slowest_int = result
        tststr += slowest_chr

cracked_hmac = crack_hmac('foo', 5) #05fa9cfa2adbcb839c66d6525dfeb23e

print(cracked_hmac)
'''
Implement and break HMAC-SHA1 with an artificial timing leak
The psuedocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing (Sinatra, web.py, whatever), 
write a tiny application that has a URL that takes a "file" argument 
and a "signature" argument, like so:

http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
Have the server generate an HMAC key, and then verify that the "signature" 
on incoming requests is valid for "file", using the "==" operator to compare 
the valid MAC for a file with the "signature" parameter (in other words, 
verify the HMAC the way any normal programmer would verify it).

Write a function, call it "insecure_compare", that implements the 
== operation by doing byte-at-a-time comparisons with early exit (ie, 
return false at the first non-matching byte).

In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).

Use your "insecure_compare" function to verify the HMACs on incoming 
requests, and test that the whole contraption works. Return a 500 if 
the MAC is invalid, and a 200 if it's OK.

Using the timing leak in this application, write a program that 
discovers the valid MAC for any file.

Why artificial delays?
Early-exit string compares are probably the most common source of 
cryptographic timing leaks, but they aren't especially easy to exploit. 
In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python) 
probably aren't exploitable over a wide-area network at all. To play with 
attacking real-world timing leaks, you have to start writing low-level 
timing code. We're keeping things cryptographic in these challenges.
'''