
![tealess](tealess.png)

----

NOTE: This project is not yet ready for general use. We're still figuring out
what we want it to do and what interfaces it should provide for users.

----

Overview: This project is intended to provide tooling that bridges several gaps
users have with various SSL/TLS.

Goals:

* Provide actionable diagnostic and error messages for SSL/TLS problems.
* Clearer explanations of problems when they occur.
* Help users break the habit of disabling certificate validation

Delivery:

1. A command-line tool to help users diagnose and repair SSL/TLS problems.
2. A Java library that can be used from other applications to provide users with actionable SSL/TLS diagnostics.


-----


Random notes:

## OpenSSL to Java Keystore

### Making a keystore from a private key + certificate

```
# Take lumberjack.key and lumberjack.crt and convert it to a single file PKCS12 format
# The '-name mykey' will create this as an alias called 'mykey'
% openssl pkcs12 -export -inkey lumberjack.key -in lumberjack.crt -name mykey > example.keystore
Enter Export Password:
Verifying - Enter Export Password:

# The java keystore tool can read this PKCS12 file format:
% keystore -list -keystore example.keystore
Keystore type: JKS
Keystore provider: SUN

Your keystore contains 1 entry

mykey, Oct 25, 2016, PrivateKeyEntry, 
Certificate fingerprint (SHA1): F0:AE:4E:D5:A5:F9:CC:7E:31:44:C2:46:7B:AF:2C:17:1E:B3:2F:BB
```
