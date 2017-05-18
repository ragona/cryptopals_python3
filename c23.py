from pals import utils 

def get_bit_from_left(n, i):
    if i < 0: return 0
    return (n >> (31 - i)) & 1

def set_bit_in_number(n, i, bit):
    return n | (bit << (31 - i))

def undo_right_shift_xor(y, shift_len):
    z = 0
    for i in range(32):
        bit = get_bit_from_left(y, i) ^ get_bit_from_left(z, i - shift_len)
        z = set_bit_in_number(z, i, bit)
    return z

a = 240
b = a ^ a >> 4
c = undo_right_shift_xor(b, 4)
print(a, b, c)
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
    return y
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