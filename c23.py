from pals import utils 

def get_bit(number, i):
    if i < 0 or i > 31:
        return 0
    return (number >> (31 - i)) & 1

def undo_right_xor(number, shift_dist):
    #

def undo_left_xor_and(number, shift_dist, andN):
    #

"""
# Right shift by 11 bits
y = y ^ y >> 11
# Shift y left by 7 and take the bitwise and of 2636928640
y = y ^ y << 7 & 2636928640
# Shift y left by 15 and take the bitwise and of y and 4022730752
y = y ^ y << 15 & 4022730752
# Right shift by 18 bits
y = y ^ y >> 18
"""
def untemper(y):
    #oh this is not nearly sufficient. D: 
    

def _int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

mt = utils.MT19937(0) 
a = mt.extract_number()
b = untemper(a)
print('y', _int32(b))
exit(0)
print('one')
a = [mt.extract_number() for i in range(624)]
b = [untemper(y) for y in a]

print('two')
mt2 = utils.MT19937(0)
mt2.replace_state(b)

print('three')
c = [mt2.extract_number() for i in range(5)]

print(a[:5])
print(c)

'''
Clone an MT19937 RNG from its output
The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. 
By permuting state regularly, MT19937 achieves a period of 
2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state 
is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" 
function that takes an MT19937 output and transforms it back into 
the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the 
operations in the temper transform in reverse order. There are two 
kinds of operations in the temper transform each applied twice; one is 
an XOR against a right-shifted value, and the other is an XOR against a 
left-shifted value AND'd with a magic number. So you'll need code to invert 
the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it 
for 624 outputs, untemper each of them to recreate the state of the generator, 
and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.

Stop and think for a second.
How would you modify MT19937 to make this attack hard? What would happen 
if you subjected each tempered output to a cryptographic hash?
'''