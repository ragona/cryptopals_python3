from pals import utils 
import random
import time 

#brute force. 
def get_seed(start, iterations, target):
    for i in range(start, start+iterations):
        mt = utils.MT19937(i)
        if mt.extract_number() == target:
            return i
    raise Exception("couldn't find seed")

#set random seed
ts = int(time.time())
rand_seed = ts + random.randint(40, 1000)
print("actual seed is", rand_seed)
#get first number in sequence
i = utils.MT19937(rand_seed).extract_number()
#crack seed 
cracked_seed = get_seed(ts, ts+1000, i)
print(" guess seed of", cracked_seed)

'''
Crack an MT19937 seed
Make sure your MT19937 accepts an integer seed value. Test it 
(verify that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

Wait a random number of seconds between, I don't know, 40 and 1000.
Seeds the RNG with the current Unix timestamp
Waits a random number of seconds again.
Returns the first 32 bit output of the RNG.
You get the idea. Go get coffee while it runs. Or just simulate the passage 
of time, although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.
'''