#!/bin/bash -x

# ENV setup
if [ -z "$SNYK_INSTALL_DIR" ]; then
  SNYK_INSTALL_DIR=$SAST_DIR/snyk
fi

mkdir -p $SNYK_INSTALL_DIR

# Install Snyk
curl https://static.snyk.io/cli/latest/snyk-linux -o $SNYK_INSTALL_DIR/snyk
chmod +x $SNYK_INSTALL_DIR/snyk

export PATH=$SNYK_INSTALL_DIR:$PATH

snyk auth $SNYK_TOKEN

# Verify Snyk installation
snyk --version