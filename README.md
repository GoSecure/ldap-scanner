# ldap-scanner scanner

Checks for signature requirements over LDAP.
The script will establish a connection to the target host(s) and request
authentication without signature capability. If this is accepted, it means that the target hosts
allows unsigned LDAP sessions and NTLM relay attacks are possible to this LDAP service (whenever signing is not requested by the client).

# Installation

```
$ pip install impacket
$ python3 ldap-scanner.py
```


# Usage
```
[*] ldap scanner by @romcar / GoSecure - Based on impacket by SecureAuth
usage: ldap-scanner.py [-h] [-target-file file]
               [-hashes LMHASH:NTHASH]
               target

ldap scanner - Connects over LDAP and attempts to authenticate with
invalid NTLM packets. If accepted, target is vulnerable to relay attack

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit

connection:
  -target-file file     Use the targets in the specified file instead of the
                        one on the command line (you must still specify
                        something as target name)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
```
