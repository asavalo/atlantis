#! /bin/bash

echo "Running all static analysis tools"

echo "Running Semgrep"
run_semgrep.sh || echo "Semgrep failed"
if [ $? -ne 0 ]; then
    echo "Semgrep failed"
else 
    echo "Semgrep succeeded"
fi

echo "Running Snyk"
run_snyk.sh || echo "Snyk failed"
if [ $? -ne 0 ]; then
    echo "Snyk failed"
else 
    echo "Snyk succeeded"
fi

# echo "Running Joern"
# run_joern.sh
# if [ $? -ne 0 ]; then
#     echo "Joern failed"
# else 
#     echo "Joern succeeded"
# fi

# echo "Running Sonarqube"
# run_sonarqube.sh || echo "Sonarqube failed"
# if [ $? -ne 0 ]; then
#     echo "Sonarqube failed"
# else 
#     echo "Sonarqube succeeded"
# fi

echo "All static analysis tools finished"