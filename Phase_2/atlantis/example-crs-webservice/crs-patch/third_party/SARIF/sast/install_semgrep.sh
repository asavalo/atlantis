#!/bin/bash -x

# ENV setup
if [ -z "$SEMGREP_INSTALL_DIR" ]; then
  SEMGREP_INSTALL_DIR=$SAST_DIR/semgrep
fi

# mkdir -p $SEMGREP_INSTALL_DIR

# Install Semgrep
pip install semgrep

semgrep login

export PATH=$SEMGREP_INSTALL_DIR:$PATH

# Verify Semgrep installation
semgrep --version
