#!/bin/bash -x

# ENV setup
if [ -z "$SONARQUBE_INSTALL_DIR" ]; then
  SONARQUBE_INSTALL_DIR=$SAST_DIR/sonarqube
fi

mkdir -p $SONARQUBE_INSTALL_DIR

# Install Snyk
curl https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-7.0.2.4839-linux-x64.zip -o $SONARQUBE_INSTALL_DIR/sonar-scanner-cli.zip
unzip $SONARQUBE_INSTALL_DIR/sonar-scanner-cli.zip -d $SONARQUBE_INSTALL_DIR
mv $SONARQUBE_INSTALL_DIR/sonar-scanner-7.0.2.4839-linux-x64 $SONARQUBE_INSTALL_DIR/sonar-scanner

rm $SONARQUBE_INSTALL_DIR/sonar-scanner-cli.zip

export PATH=$SONARQUBE_INSTALL_DIR/sonar-scanner/bin:$PATH

# export SONAR_TOKEN=squ_5fec8100f55044263fa71686f286c07043674008
export SONAR_TOKEN=342800506018bb38512299e4aae9440b323334fa

# sed -i 's/#sonar.host.url=https:\/\/mycompany.com\/sonarqube/sonar.host.url=http:\/\/localhost:9000/' $SONARQUBE_INSTALL_DIR/sonar-scanner/conf/sonar-scanner.properties
# sed -i 's/#sonar.host.url=https:\/\/mycompany.com\/sonarqube/sonar.host.url=http:\/\/localhost:9000/' $SONARQUBE_INSTALL_DIR/sonar-scanner/conf/sonar-scanner.properties

# Add project settings
echo "sonar.host.url=https://sonarcloud.io" >> $SONARQUBE_INSTALL_DIR/sonar-scanner/conf/sonar-scanner.properties
echo "sonar.projectKey=sarif-test_sarif-test" >> $SONARQUBE_INSTALL_DIR/sonar-scanner/conf/sonar-scanner.properties
echo "sonar.organization=sarif-test" >> $SONARQUBE_INSTALL_DIR/sonar-scanner/conf/sonar-scanner.properties

# sonar.cfamily.compile-commands
# echo "sonar.cfamily.compile-commands=cmake -Bbuild -H." >> $SONARQUBE_INSTALL_DIR/sonar-scanner/conf/sonar-scanner.properties

# Verify Snyk installation
sonar-scanner --version