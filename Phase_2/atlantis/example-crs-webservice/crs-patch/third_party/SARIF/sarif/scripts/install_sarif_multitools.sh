# !/bin/bash

# Install libssl1.1 for old dotnet 3.1
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.0g-2ubuntu4_amd64.deb
sudo dpkg -i libssl1.1_1.1.0g-2ubuntu4_amd64.deb

# # Install node and npm
sudo apt-get install -y nodejs npm
npm i -g @microsoft/sarif-multitool
# RUN CMD Example: npx @microsoft/sarif-multitool validate user-nginx_cpv-5.sarif --output user-nginx_cpv-5-validate.sarif