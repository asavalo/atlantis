ARG IMG_TAG=latest
FROM ghcr.io/aixcc-finals/base-runner-debug:${IMG_TAG}

# Issue: gdb, gdbserver and python-3.10 in /usr/local/bin directory cause an unknown issue with RR. So disable them by removing files in "/usr/local/bin"
RUN rm /usr/local/bin/*

RUN apt update 

RUN apt install -y libpython3-dev libmpfr-dev python3-pip 
RUN rm -rf /var/lib/apt/lists/*

RUN pip3 install capstone pandas

COPY install-gdb.sh /usr/local/bin/install-gdb.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/install-gdb.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN install-gdb.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
