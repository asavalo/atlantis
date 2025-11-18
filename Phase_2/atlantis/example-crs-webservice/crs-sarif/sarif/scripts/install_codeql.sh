# !/bin/bash

cd /tmp
wget https://github.com/github/codeql-cli-binaries/releases/download/v2.20.4/codeql-linux64.zip --no-check-certificate
unzip codeql-linux64.zip
mv codeql /opt/codeql
rm codeql-linux64.zip
ln -s /opt/codeql/codeql /usr/local/bin/codeql

cd -
cd ./sarif/sarif/codeql/ql
cd c
codeql pack install

cd -
cd ./sarif/sarif/codeql/ql
cd java
codeql pack install
