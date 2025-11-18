curdir=$(realpath $(dirname $0))
cd $curdir/src/sample && mvn install
cd $curdir/src/sample-harnesses && mvn package
mkdir -p $curdir/out/harnesses/one
cp -rf $curdir/src/sample-harnesses/sample-harness-one/target/sample-harness-one-1.0.0-SNAPSHOT.jar $curdir/out/harnesses/one
cp -rf $curdir/src/sample-harnesses/sample-harness-one/target/lib/*.jar $curdir/out/harnesses/one
