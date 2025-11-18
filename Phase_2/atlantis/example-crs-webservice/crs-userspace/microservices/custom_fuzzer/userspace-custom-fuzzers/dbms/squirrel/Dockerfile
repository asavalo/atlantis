FROM ghcr.io/aixcc-finals/base-runner:v1.3.0

COPY ./data /root/data
COPY ./build /root/build
COPY ./run.py /root/run.py
RUN python3 -m pip install pyyaml 

RUN chmod +x /root/data/run.sh
