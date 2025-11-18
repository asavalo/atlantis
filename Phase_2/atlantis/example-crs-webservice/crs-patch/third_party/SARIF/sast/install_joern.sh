#!/bin/bash -x

# ENV setup
if [ -z "$JOERN_INSTALL_DIR" ]; then
  JOERN_INSTALL_DIR=$SAST_DIR/joern
fi

if [ -z "$JOERN_VERSION" ]; then
  JOERN_VERSION=v4.0.258
fi

mkdir -p $JOERN_INSTALL_DIR

# Install Joern
pushd /tmp

wget https://github.com/joernio/joern/releases/download/$JOERN_VERSION/joern-install.sh --no-check-certificate
chmod +x joern-install.sh
./joern-install.sh --install-dir=$JOERN_INSTALL_DIR --version=$JOERN_VERSION --reinstall

rm joern-install.sh
rm joern-cli.zip

export PATH=$JOERN_INSTALL_DIR/joern-cli:$JOERN_INSTALL_DIR/joern-cli/bin:$PATH

popd

# Verify Joern installation
# $JOERN_INSTALL_DIR/joern-cli/joern -h