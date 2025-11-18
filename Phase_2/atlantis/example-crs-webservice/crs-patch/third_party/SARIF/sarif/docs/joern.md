# Installation
- Please refer to ./scripts/install_joern.sh for installation steps.

## Install Joern
```bash
export JOERN_INSTALL_DIR=/opt/joern
export JOERN_VERSION=v4.0.258

wget https://github.com/joernio/joern/releases/download/$JOERN_VERSION/joern-install.sh --no-check-certificate
chmod +x joern-install.sh
./joern-install.sh --install-dir=$JOERN_INSTALL_DIR --version=$JOERN_VERSION --reinstall

rm joern-install.sh
rm joern-cli.zip
```
