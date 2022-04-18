A simple remote triggering POC for CVE-2022-0778 

### Why
While trying to validate whether server implementations on our side where/are vulnerable to CVE-2022-0778, it
proved extremely cumbersome to do so remotely. Instructions to create maliciously crafted certificates to trigger
the parsing bug in `BN_nod_sqrt()` [have been around](https://github.com/drago-96/CVE-2022-0778) for a while now
but the main issue is that most client implementations would try to parse the client certificate in order to use
it in the TLS handshake. This in turn meant, that 
- if the implementation was vulnerable the bug would be triggered and the client consume 100% and stall. 
- if the implementation was not vulnerable, the certificate could not be parsed and client would, rightfully so, exit.

### What
What was actually needed, was to be able to inject a message in the TLS handshake so that we can replace the contents
of the Certificate message that the client sends to the server in response to the CertificateRequest message. 

### How
This depends on  [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng) and overrides the `TLSConnection._clientKeyExchange` 
method so that during a TLS handshake with a possibly vulnerable server:

1. We send a ClientHello message as we would normally do
2. We consume the ServerHelloMessage and check if it contains a CertificateRequest
3. If it does, we construct an arbitrary Certificate message, loading the DER encoded crafted certificate from disk
4. Send the crafted message to the server and expect it will parse it, possibly triggering CVE-2022-0778 

The `crafted.crt` is created based on the instructions in https://github.com/drago-96/CVE-2022-0778#using-asn1-templates, 
feel free to recreate this if you wish so. 

### Usage
```
usage: main.py [-h] [--server SERVER] [--port PORT]

Parameters

optional arguments:
  -h, --help       show this help message and exit
  --server SERVER  Name of the server to connect for the TLS handshake,
                   defaults to "localhost"
  --port PORT      Port where server listens for TLS connections, defaults to
                   "443"
```