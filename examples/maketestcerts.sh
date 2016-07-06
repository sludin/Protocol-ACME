CERT_DIR=./certs
ACCOUNT_KEY=$CERT_DIR/test_account_key.pem
CERT_KEY=$CERT_DIR/test_cert_key.pem
CSR=$CERT_DIR/test_csr.der
SUBJECT="/CN=www.ludin.org"

#  Generate a new private key for the Let's Encrypt account. For example:

openssl genrsa -out $ACCOUNT_KEY 2048

#  Generate a new private key for the certificate. For example:

openssl genrsa -out $CERT_KEY 2048

#  Generate a certificate signing request (CSR).  For example (for a single domain cert):
#    $ openssl req -new -sha256 -key cert_key.pem -outform der -subj "/CN=cloud.ludin.org" > csr.der
#
#  Generating a CSR for a SAN cert ( multiple domains ) is a bit more work.  Grab a version
#    of openssl.cnf and add the following:
#
#    [SAN]
#    subjectAltName=DNS:domain1.example.com,DNS:domain2.example.com
#
#   and then generate with something like:
#

openssl req -new -out $CSR -outform der -key $CERT_KEY -config $CERT_DIR/openssl.cnf -reqexts SAN -subj $SUBJECT -sha256

