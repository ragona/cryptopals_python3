#Convert hex to base64

#attempt 1
#decoding myself to learn about the formats
#using no imported libraries

base64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#decodes hex and then encodes base64
#this will first create a long string of binary patterns with 8 characters representing
#each hexidecimal octet, and then go through this string six characters at a time and 
#convert them to an integer, and then use that integer as an index to the base 64 table
#to replace them
def hexToBase64(hs):
	bit_string = ""
	for i in range(0, len(hs) / 2):
		#grab the two character hex value (i.e. 4d)
		hexChar = hs[i * 2 : i * 2 + 2]
		#covert it to an int so we can format it as a bit pattern (4d -> 77)
		intChar = int(hexChar, 16)
		#format it as a bit pattern (i.e. 77, bin(77) is 1001101, we want 01001101
		#if it was 1, we'd want 00000001; this ensures padding.)
		bit_string += format(intChar, "08b")

	#produce the encoded string
	#TODO: make this pad correctly for bit_string % 24 != 0
	b64s = ""
	for i in range(0, len(bit_string) / 6):
		#grab the 6 bit chunk
		chunk = bit_string[i * 6 : i * 6 + 6]
		#convert it to an int to get the right index in the base64 table
		b64i = int(chunk, 2)
		#grab the corresponding char from the table and add it to the return
		b64s += base64table[b64i]

	return b64s
	


hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
want = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

got = hexToBase64(hex_input)

print got
print got == want

#attempt 2
#the easy way
import base64

print "the short way"
conv_ascii = hex_input.decode("hex")
b64out = base64.b64encode(conv_ascii)
print b64out
print b64out == want

#attempt 3
#the right way (and incidentally also the short way, I suppose)
import binascii
import base64

print base64.b64encode(binascii.unhexlify(hex_input))
