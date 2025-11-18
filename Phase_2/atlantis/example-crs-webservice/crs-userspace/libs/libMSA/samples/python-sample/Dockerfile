FROM python:3.10-slim

COPY libmsa /usr/src/libmsa
WORKDIR /usr/src/libmsa
RUN pip install .

COPY proto /usr/src/python-sample/proto

COPY run.py /usr/src/python-sample/run.py
WORKDIR /usr/src/python-sample

CMD ["python3", "run.py", "python_sample", "2", "topic2", "python-sample", "topic3"]