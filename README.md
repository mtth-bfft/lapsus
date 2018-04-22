# Lapsus

A standalone miniature tool to reset the local administrator password of each computer in your Windows fleet to a random value, stored encrypted in a central registry (on a network share, for instance).

It can be used as a temporary replacement for [LAPS (the official Microsoft solution)](https://technet.microsoft.com/en-us/mt227395.aspx), which additionally handles automatic periodic rotation, audit trails, and uses more secure dedicated AD attributes. Useful for Active Directory incident response & remediation, when you realise that your client has the same password everywhere, or generates them using a world-readable script in their sysvol (oopsie), and you don't have the time for a full LAPS installation with schema extension.

# Installation

You need Visual Studio to compile this project. Simply ``git clone`` it and open the .sln file. There is no external dependency, asymmetrical cryptography is handled by Microsoft's CryptoAPI.

This version should run on Windows XP all the way to Windows 10. If you find incompatible versions, please open an issue.

# Usage

1. Create an empty world-appendable and Domain-Admins-readable CSV list of machine-account-passwords (passwords will be encrypted, but you should throw in a NTFS ACL for good measure) :

```
type nul > \\srv\pwdshare\db.csv
icacls \\srv\pwdshare\db.csv /grant:r "MYDOM\\Domain Admins:(F)" /grant:r "*S-1-1-0:(Rc,S,AD)"
icacls \\srv\pwdshare\db.csv /inheritance:r
icacls \\srv\pwdshare\db.csv /setowner "MYDOM\\Domain Admins"
```

2. Generate a RSA key pair, with the public key in the same share, and the private key in a safe place:

```
lapsus.exe /genkey \\srv\pwdshare\pub.key .\priv.key 4096
```

3. Copy lapsus.exe to the same share, and make sure that everyone can append data to the CSV file, read the public key, and execute the binary

4. Create a GPO applying an immediate scheduled task, executing:

```
\\srv\pwdshare\lapsus.exe /randomize \\srv\pwdshare\pub.key \\srv\pwdshare\db.csv RID500
```

5. When needed, read a machine's RID 500 account password from the encrypted db.csv :

```
lapsus.exe /decrypt .\priv.key \\srv\pwdshare\db.csv MYMACHINE
```

By default, concurrent accesses to the file are handled by waiting with an exponential backoff, with a maximum total wait of 1 hour.

# Contributing

I'd be glad to know if you found this tool useful. Send me remarks and suggestions @mtth_bfft. Pull requests welcome.
