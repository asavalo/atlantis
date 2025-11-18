#!/bin/bash

#set -e

wait_cp_tarball() {
    # TODO: handle venilla TARBALL_DIR for llm-poc-gen as well
    JAVACRS_TARBALL_DIR=${JAVACRS_TARBALL_DIR:-/tarballs}
    if [ "$JAVACRS_TARBALL_DIR" != "/tarballs" ]; then
        FILE=$JAVACRS_TARBALL_DIR/DONE
        while [ ! -e "$FILE" ]; do
            echo "Waiting for $FILE to be created..."
            sleep 1  # Adjust the sleep duration as needed
        done
    else
        echo WARN: raw tarball /tarballs received, this may not be the expected usage
    fi
}

setup_src_proj() {
    src_proj=/src/oss-fuzz/projects/$CRS_TARGET
    rm -rf $src_proj
    mkdir -p $src_proj
    tar --use-compress-program=pigz -xf $JAVACRS_TARBALL_DIR/project.tar.gz -C $src_proj
    mkdir -p $src_proj/.aixcc/
    if [ -e $JAVACRS_TARBALL_DIR/ref.diff ]; then
        echo "Diff mode: $JAVACRS_TARBALL_DIR/ref.diff"
        rsync -a $JAVACRS_TARBALL_DIR/ref.diff $src_proj/ref.diff
    else
        echo "Full mode"
    fi
    # Skip the .aixcc config.yaml for now
    #if [ -e $JAVACRS_TARBALL_DIR/aixcc_conf.yaml ]; then
    #    rsync -a $JAVACRS_TARBALL_DIR/aixcc_conf.yaml $src_proj/.aixcc/config.yaml
    #else
    #    echo "$JAVACRS_TARBALL_DIR/aixcc_conf.yaml does not exist; ok for local test"
    #fi
}

setup_src_repo() {
    src_repo=/src/repo
    rm -rf $src_repo
    mkdir -p $src_repo
    tar --use-compress-program=pigz -xf $JAVACRS_TARBALL_DIR/repo.tar.gz -C $src_repo
}

setup_out() {
    out_dir=/out
    rm -rf $out_dir
    mkdir -p $out_dir
    tar --use-compress-program=pigz -xf $JAVACRS_TARBALL_DIR/fuzzers.tar.gz -C $out_dir
    # TODO: Check this before every AFC submission
    # Ref: https://github.com/aixcc-finals/oss-fuzz-aixcc/blob/aixcc-afc/infra/base-images/base-builder/compile#L180
    find $out_dir -type f | while read f;
    do
      if [[ $(basename "$f") =~ ^jazzer.*$ ]]; then
        if [[ "$basename" != "jazzer_driver_with_sanitizer" ]]; then
          rm -f "$f"
        fi
      fi
    done
    rsync -a $JAVA_CRS_SRC/jazzer_driver_stub $out_dir/jazzer_driver
}

setup_cp_dirs() {
    wait_cp_tarball
    setup_src_proj
    setup_src_repo
    setup_out
}

update_crs_cfg() {
    DEFAULT_CFG="$JAVA_CRS_SRC/crs-java.config"
    if [ -z "$JAVACRS_CFG" ]; then
        echo "Using default crs-java.config (JAVACRS_CFG is not set)"
    else
        echo "Custom configuration detected: $JAVACRS_CFG"
        if [ -e $JAVACRS_CFG ]; then
            python3.12 javacrscfg.py merge-crs-cfg "$DEFAULT_CFG" "$JAVACRS_CFG"
            echo "Successfully merged custom config into crs-java.config"
        else
            echo "$JAVACRS_CFG does not exists, using default crs-java.config"
        fi
    fi
}

run_crs() {
    pushd $JAVA_CRS_SRC > /dev/null

    update_crs_cfg

    export JAVA_CRS_IN_COMPETITION=1

    python3.12 -u ./main.py $DEFAULT_CFG 2>&1 | tee ./crs-java.log

    popd > /dev/null
}

# Comment
#mock_k8s_env() {
#    export JAVACRS_TARBALL_DIR=/new-task/crs-java
#    export FUZZING_ENGINE=libfuzzer
#    export CRS_TARGET=mock-java
#    export JAVACRS_CFG=/new-task/crs-java/0.json
#    export SANITIZER=address
#    export HELPER=True
#    export RUN_FUZZER_MODE=interactive
#}
#
#if [ ! -z "$MOCK_K8S_TESTING" ]; then
#    mock_k8s_env
#fi

setup_sys() {
    ulimit -c 0
    sysctl -w fs.file-max=2097152
    sysctl -w fs.inotify.max_user_instances=512
}

setup_cp_dirs
setup_sys
run_crs
