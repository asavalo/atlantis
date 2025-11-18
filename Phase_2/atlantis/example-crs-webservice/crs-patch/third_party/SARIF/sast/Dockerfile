ARG BASE_IMAGE_NAME

FROM $BASE_IMAGE_NAME

RUN apt-get update && \
    apt-get install -y openjdk-21-jdk libssl1.1 curl && \
    apt-get clean

RUN apt-get install -y --reinstall libssl1.1 libcurl4 && \
    ln -sf /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/local/lib/libssl.so.1.1 && \
    ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/local/lib/libcrypto.so.1.1 && \
    ldconfig

ARG SONAR_TOKEN
ARG SEMGREP_APP_TOKEN
ARG SNYK_TOKEN

ENV SONAR_TOKEN=$SONAR_TOKEN
ENV SEMGREP_APP_TOKEN=$SEMGREP_APP_TOKEN
ENV SNYK_TOKEN=$SNYK_TOKEN

ENV SAST_DIR=/sast

ENV SONARQUBE_INSTALL_DIR=$SAST_DIR/sonarqube
ENV SNYK_INSTALL_DIR=$SAST_DIR/snyk
ENV SEMGREP_INSTALL_DIR=$SAST_DIR/semgrep
ENV JOERN_INSTALL_DIR=$SAST_DIR/joern

ENV PATH=$SAST_DIR/bin:$SONARQUBE_INSTALL_DIR/sonar-scanner/bin:$SNYK_INSTALL_DIR:$SEMGREP_INSTALL_DIR:$JOERN_INSTALL_DIR/joern-cli:$JOERN_INSTALL_DIR/joern-cli/bin:$PATH

COPY install_*.sh $SAST_DIR/bin/
COPY run_*.sh $SAST_DIR/bin/

RUN install_semgrep.sh
RUN install_snyk.sh
RUN install_joern.sh
RUN install_sonarqube.sh

CMD ["run_all.sh"]