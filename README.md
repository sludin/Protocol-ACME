# Protocol::ACME

See client.pl for an example of using the library.

# Status

This module is very rough right now.  The goal is to get feedback on key items such as:

* Naming
* Challenge handling
* Exception handling 

# Usage

## Requisite file creation

In order to use the library and the Let's Encrypt service in general you will need to generate a couple of files.  These are:

* A private account key 
* A private cetificate key
* A certificate signing request ( CSR )

There are numerous ways to go about this.  Below are some command line recipies using OpenSSL.

1) Generate a new private key for the Let's Encrypt account: 
 
 `$ openssl genrsa -out account_key.pem 2048`
 
2) Generate a new private key for the certificate:
 
 `$ openssl genrsa -out cert_key.pem 2048`

3a) Generate a certificate signing request (CSR).  For a single domain cert:

`$ openssl req -new -sha256 -key cert_key.pem -outform der -subj "/CN=cloud.example.com" > csr.der`

 3b) Generating a CSR for a SAN cert ( multiple domains ) is a bit more work.  Grab a version of openssl.cnf and add the following:

```
   [SAN]
   subjectAltName=DNS:domain1.example.com,DNS:domain2.example.com
```

  and then generate with something like:

`$ openssl req -new -out test.csr -outform der -key cert_key.pem -config openssl.cnf -reqexts SAN -subj "/CN=domain.example.com" -sha256`

  This will create a cert with three domains.  domain.example.com will be in the subject and
  domain1.example.com and domain2.example.com will be in the SAN extension.

# API Usage

The goal of this module is to take away much of the need to understand the details of the Let's Encrypt ACME api.  That said, having a rough understanding of the flow will be usefil.  client.pl was writted and commented in a way to document the API and the manner in which to use the module.

## Challenges

The goal of the challenges code is to make it as flexible as possible by having the user provide a closure / function reference that is passed the the ACME module.  Each identifier will need its own challenge fullfillment code.

TODO: Make this multiple modules that take care of different use cases such as dropping files locally, copying via SSH, pusting to github, etc.  FLexibility is the goal.

