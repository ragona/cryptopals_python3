from pals import utils 
import random

'''
I've really struggled with this one. Bitwise operations
are not something I've spent much time with, and this 
has been a super valuable learning experience. But also
damn, it's really taken some time for me to bang my head
through these problems. 
'''

#get least significant bit  
def get_bit_from_left(n, i):
    if i < 0: return 0
    return (n >> (31 - i)) & 1

#get most significant bit
def get_bit_from_right(n, i):
    if i < 0: return 0
    return n >> i & 1

#set a bit within a number (n)
def set_bit(n, i, bit):
    return n | (bit << i)

def undo_right_shift_xor(y, shift_len):
    x = 0
    for i in range(32):
        bit = get_bit_from_left(y, i) ^ get_bit_from_left(x, i - shift_len)
        x = set_bit(x, 31 - i, bit)
    return x

def undo_left_shift_xor_and(y, shift_len, constant):
    x = 0
    for i in range(32):
        ybit = get_bit_from_right(y, i)
        xbit = get_bit_from_right(x, i - shift_len)
        cbit = get_bit_from_right(constant, i)
        x = set_bit(x, i, ybit ^ (xbit & cbit))
    return x

"""
Operation to undo:
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
    y = undo_right_shift_xor(y, 18)
    y = undo_left_shift_xor_and(y, 15, 4022730752)
    y = undo_left_shift_xor_and(y, 7, 2636928640)
    y = undo_right_shift_xor(y, 11)
    return y

#new generator
mt = utils.MT19937(random.randrange(0, 2 << 32))

#clone state
cloned_state = [untemper(mt.extract_number()) for i in range(624)]

#make sure state does equal cloned state
print(mt.mt == cloned_state)

#make sure output is identical
cloned_mt = utils.MT19937(0)
cloned_mt.replace_state(cloned_state)
print(mt.extract_number() == cloned_mt.extract_number())

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