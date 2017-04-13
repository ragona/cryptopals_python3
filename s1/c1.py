#Convert hex to base64


base64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def hexToBase64(hs):
	#produce a long string of bit patterns representing each 2 character hex value
	bit_string = ""
	for i in range(0, len(hs) / 2):
		#grab the specific two character hex value
		bit_string += bitStringFromHexChar(hs[i * 2 : i * 2 + 2])

	#produce the encoded string
	#TODO: make this pad correctly
	b64s = ""
	for i in range(0, len(bit_string) / 6):
		#grab the 6 bit crunk
		chunk = bit_string[i * 6 : i * 6 + 6]
		#convert it to an int to get the right index in the base64 table
		b64i = int(chunk, 2)
		#grab the corresponding char from the table and add it to the return
		b64s += base64table[b64i]

	return b64s

def bitStringFromHexChar(hexChar):
	#covert it to an int so we can format it as a bit pattern
	intChar = int(hexChar, 16)
	#format it as a bit pattern 
	return format(intChar, "08b")


hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
want = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

got = hexToBase64(hex_input)

print got == want
