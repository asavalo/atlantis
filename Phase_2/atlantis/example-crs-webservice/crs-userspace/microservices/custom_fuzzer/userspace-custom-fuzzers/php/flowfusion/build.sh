#!/bin/bash
# assume php-src is already mounted in /src directory
sudo chown -R phpfuzz:phpfuzz /home/phpfuzz/WorkSpace
cp -r /src/. ./php-src
cp -r ./php-langspec ./php-src
cd php-src;
git init;
find ./ -name "*.phpt" > /tmp/flowfusion-prepare.log;
cd ..; 
python3 prepare.py;