FROM cruizba/ubuntu-dind@sha256:3d829640d326a83054e259f99038268700b848602d8bc83956c54716170c87b6

# Disable interactive dialogs during build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y curl git build-essential libssl-dev zlib1g-dev \
    sqlite3 libsqlite3-dev libffi-dev libbz2-dev libncurses-dev libreadline-dev liblzma-dev \
    && curl https://pyenv.run | bash
ENV PATH="/root/.pyenv/bin:/root/.pyenv/shims:$PATH"
RUN pyenv install 3.10.14 && pyenv global 3.10.14

RUN apt install -y rsync redis-server pigz

RUN curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
    tee /etc/apt/sources.list.d/elastic-8.x.list
RUN apt update && apt install filebeat -y

RUN git config --global user.email "atlanta@team.com"
RUN git config --global user.name "Team Atlanta"

WORKDIR /app
COPY crs-multilang/requirements.txt requirements.txt
COPY crs_webserver/pyproject.toml ./crs_webserver/pyproject.toml
RUN pip install -r requirements.txt
WORKDIR /app/crs_webserver
RUN pip install --no-cache-dir .

WORKDIR /app
COPY cp_manager/libs/libCRS libs/libCRS
RUN pip install libs/libCRS

WORKDIR /app
COPY crs_webserver/my_crs ./crs_webserver/my_crs
WORKDIR /app/crs_webserver
RUN pip install .

WORKDIR /app
COPY cp_manager/patch_client ./patch_client
WORKDIR /app/patch_client
RUN pip install .

WORKDIR /app
COPY cp_manager/sarif_client ./sarif_client
WORKDIR /app/sarif_client
RUN pip install .

WORKDIR /app
COPY cp_manager/cp_manager/pov_deduplication ./pov_deduplication
WORKDIR /app/pov_deduplication
RUN pip install -r requirements.txt
RUN pip install --ignore-requires-python clusterfuzz/src

RUN pip install docker

WORKDIR /app
COPY crs-multilang/run.py bin/crs-multilang.py
COPY crs-multilang/azure-other-services.yml bin/azure-other-services.yml
COPY crs-multilang/libs/oss-fuzz/infra/helper.py bin/helper.py
COPY crs-multilang/scripts/filter-harness.py bin/scripts/filter-harness.py
COPY cp_manager/cp_manager ./cp_manager
COPY cp_manager/vapi_server ./vapi_server

EXPOSE 80
CMD ["uvicorn", "vapi_server.main:app", "--host", "0.0.0.0", "--port", "80", "--log-level", "info"]
