#!/bin/bash

cd $(dirname $0)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=IT/L=Bologna/O=alessandropira.it/OU=test/CN=localhost"

