# Installation
- To run codeql locally, you need to install codeql and query packs.
- Please refer to ./scripts/install_codeql.sh for installation steps.

## Install CodeQL binary
```bash
wget https://github.com/github/codeql-cli-binaries/releases/download/v2.20.4/codeql-linux64.zip --no-check-certificate
unzip codeql-linux64.zip
mv codeql /opt/codeql
rm codeql-linux64.zip
ln -s /opt/codeql/codeql /usr/local/bin/codeql
```

## Install query packs for the reachability analysis
```bash
cd $WORK_DIR/sarif/sarif/codeql/ql/c
codeql pack install

cd $WORK_DIR/sarif/sarif/codeql/ql/java
codeql pack install
```