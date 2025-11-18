#!/bin/bash

export PATH=/work/mvn-wrapper:$PATH

# sdkman prepends the PATH to mvn, so we need to prepend ours again.
SDKMAN_INIT=$HOME/.sdkman/bin/sdkman-init.sh
if [ -s $SDKMAN_INIT ]; then
    echo >> $SDKMAN_INIT
    echo 'export PATH=/work/mvn-wrapper:$PATH' >> $SDKMAN_INIT
fi
unset SDKMAN_INIT
