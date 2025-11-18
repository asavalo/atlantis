FROM ghcr.io/aixcc-finals/base-runner

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    wget \
    tar \
    python3 \
    python3-pip

RUN python3 -m pip install loguru pydantic 

ENV CRS_SARIF_TRACER_TRACE_TOOL_DIR=/trace-tool
COPY ./tools $CRS_SARIF_TRACER_TRACE_TOOL_DIR

ENV CRS_SARIF_TRACER_DYNAMORIO_TOOL_DIR=$CRS_SARIF_TRACER_TRACE_TOOL_DIR/dynamorio
ENV CRS_SARIF_TRACER_DYNAMORIO_HOME=$CRS_SARIF_TRACER_DYNAMORIO_TOOL_DIR/DynamoRIO-Linux-11.90.20147
ENV CRS_SARIF_TRACER_FUNCTION_TRACER_PLUGIN=$CRS_SARIF_TRACER_DYNAMORIO_TOOL_DIR/libfunction_trace.so

RUN cd $CRS_SARIF_TRACER_DYNAMORIO_TOOL_DIR && \
    chmod +x build.sh && \
    ./build.sh


ENV CRS_SARIF_TRACER_TRACER_PATH=/tracer

COPY ./src /$CRS_SARIF_TRACER_TRACER_PATH

WORKDIR $CRS_SARIF_TRACER_TRACER_PATH

CMD ["python3", "run.py"]