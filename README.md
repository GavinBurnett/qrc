Quantum Resistant Cryptography - qrc

Overview

qrc is a GnuPG inspired implementation of the go crypto/mlkem library.
The library implements the quantum-resistant key encapsulation method ML-KEM - see NIST FIPS 203 for further details.

Installation

Download the archive file containing the executable for the relevant operating system from the releases. Validate the PGP signature if an integrity check is advisable, and extract the executable from the archive file. Place the executable in a suitable directory; E.G /home/username/qrc

GnuPG Signing Key: http://pgp.mit.edu/pks/lookup?op=get&search=0x203092F792253A6F

Getting started

The first step is to generate a public and secret key pair:

qrc --generate-keys

Specify the owner name, owner e-mail address and file names of the public and secret keys.
Also specify the password for the secret key.
It is recommended to specify filenames that reflect the key type - E.G: public.key and secret.key
It is also advised to backup both keys to a secure storage - such as a USB key.
Finally, distribute the public key to all relevant parties, but do not distribute the secret key or the password associated with it.

The details of a key file can be displayed as follows:

qrc --show-key=public.key

Encrypting and decrypting files

A file (I.E a plain text file) can be encrypted into a cipher text file as follows:

qrc --encrypt key=public.key plaintext=plaintextfile.txt ciphertext=ciphertextfile.qrc

In this example, a file plaintextfile.txt is being encrypted into a file ciphertextfile.qrc

Note that a public key must be used for encryption.

qrc --decrypt key=secret.key ciphertext=ciphertextfile.qrc plaintext=plaintextfile.txt

In this example, a file ciphertextfile.qrc is being decrypted into a file plaintextfile.txt

Note that a secret key must be used for decryption.


WARNING: The author takes no responsibility for data loss.

Citations:

https://golang.bg/pkg/crypto/mlkem/

https://csrc.nist.gov/pubs/fips/203/final

https://www.sandrolain.com/blog/019-golang-mlkem-encryption/

https://zerotohero.dev/inbox/secure-password-input/
