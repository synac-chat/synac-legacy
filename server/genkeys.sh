#!/bin/sh

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl pkcs12 -export -inkey key.pem -in cert.pem -out cert.pfx -nodes -passout pass:
rm key.pem cert.pem
