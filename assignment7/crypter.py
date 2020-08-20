from Crypto.Cipher import AES
import argparse
import os

# Encryption of shellcode with secret
def encrypt(shellcode, secret):
    cipher = AES.new(secret, AES.MODE_ECB)
    ciphertext = cipher.encrypt(shellcode)
    return ciphertext

# Decryption of shellcode with secret
def decrypt(shellcode, secret):
    cipher = AES.new(secret, AES.MODE_ECB)
    plaintext = cipher.decrypt(shellcode)
    return plaintext

# Output of the encrypted shellcode from hex to \\x12\\x34\\x56
# this notation is neccessary for reading of the shellcode while decrypting
def output_encrypted(shellcode):
    output = ""
    for x in bytearray(shellcode):
        output += "\\x"
        output += '%02x' % x
    output = output.replace("\\x", r'\\x')
    return output

# Output of the decrypted shellcode from hex to \x12\x34\x56
def output_decrypted(shellcode):
    output = ""
    for x in bytearray(shellcode):
        if x == 0:
            break
        output += "\\x"
        output += '%02x' % x
    return output

# write a C template to file and insert the decrypted shellcode
def execution(shellcode):
    try:
        File = open("shellcode.c", "w")
        File.write("""
        #include<stdio.h>
        #include<string.h>
        unsigned char code[] = "%s"; """ % shellcode)
        #split because there is a %d for the shellcode length in the C code
        File.write("""
        int main()
        {
            printf(\"Shellcode Length:  %d\\n\", strlen(code));
            int (*ret)() = (int(*)())code;
            ret();
        }""")
        File.close()

        print("\nShellcode was written...")
        print("Executing:\n")
        # compile, link and execute the shellcode
        os.system("gcc -fno-stack-protector -z execstack -m32 shellcode.c -o shellcode && ./shellcode")
    except:
        print("Execution failed...")

if __name__ == '__main__':

    # parse the given arguments
    # -e -s <shellcode> -k <key> for encryption
    # -d -s <shellcode> -k <key> for decryption
    # -d -s <shellcode> -k <key> -x for decryption and execution
    parser = argparse.ArgumentParser(description="Crypter SLAE assignment 7")
    parser.add_argument("-e", "--encrypt", help="encrypt shellcode", dest='encrypt', action="store_true")
    parser.add_argument("-d", "--decrypt", help="decrypt shellcode", dest='decrypt', action="store_true")
    parser.add_argument("-x", "--execute", help="execute shellcode", dest='execute', action="store_true")
    parser.add_argument("-s", "--shellcode", type=str, help="shellcode to encrypt", dest='shellcode')
    parser.add_argument("-k", "--key", help="key to encrypt", dest='key')
    results = parser.parse_args()

    # Key must be a multiple of 16 bytes in AES, so we have to stretch it a bit if less bytes are provided
    encryption_key = results.key.encode()
    key_length = len(encryption_key) % AES.block_size
    if key_length != 0:
        encryption_key = encryption_key * 16
        encryption_key = encryption_key[0:16]

    print("\nKey: ")
    print(encryption_key.encode('hex') + " (" + results.key + ")")

    if results.encrypt:
        # bring the shellcode is a useful form and stretch it to a multiple of the AES block size
        shellcode = results.shellcode.replace("\\x", "")
        shellcode_padded = shellcode + (AES.block_size - (len(shellcode) % AES.block_size)) * '0'
        shellcode_padded = shellcode_padded.decode("hex")
        print("\nPlain:")
        print(shellcode_padded.encode("hex"))

        # call the encryption function and print out the encrypted shellcode
        ciphertext = encrypt(shellcode_padded, encryption_key)
        print("\nEncrypted:")
        print(ciphertext.encode('hex'))
        print("\nShellcode:")
        print("'" + output_encrypted(ciphertext) + "'\n")


    if results.decrypt:
        # bring the shellcode in a useful form - the input could be \x or \\x
        if (results.shellcode[0:2]) == "\\x":
            shellcode_padded = results.shellcode.replace("\\x", "")
        else:
            shellcode_padded = results.shellcode.replace("\\\\x","")
        shellcode_padded = shellcode_padded.decode("hex")
        print("\nPlain:")
        print(shellcode_padded.encode("hex"))
        # call the decryption function and print out the decrypted shellcode
        plaintext = decrypt(shellcode_padded, encryption_key)
        print("\nDecrypted:")
        print(plaintext.encode('hex'))
        print("\nShellcode:")
        print("'" + output_decrypted(plaintext) + "'\n")
        # if the -x argument was provided, send the decrypted shellcode to the execution function
        if results.execute:
            execution(output_decrypted(plaintext))




