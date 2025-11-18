#!/bin/bash -x

if [ -z "$JOERN_INSTALL_DIR" ]; then
  JOERN_INSTALL_DIR=/opt/joern
fi

if [ -z "$JOERN_VERSION" ]; then
  JOERN_VERSION=v4.0.258
fi

pushd /tmp

wget https://github.com/joernio/joern/releases/download/$JOERN_VERSION/joern-install.sh --no-check-certificate
chmod +x joern-install.sh
./joern-install.sh --install-dir=$JOERN_INSTALL_DIR --version=$JOERN_VERSION --reinstall

rm joern-install.sh
rm joern-cli.zip

popd
