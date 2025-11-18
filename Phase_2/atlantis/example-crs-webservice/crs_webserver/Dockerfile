FROM python:3.12-bullseye

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
    tee /etc/apt/sources.list.d/elastic-8.x.list
RUN apt update && apt install filebeat -y


COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY ./libs/libCRS ./libs/libCRS
RUN pip3 install ./libs/libCRS
RUN pip3 install openai

COPY my_crs ./my_crs
COPY scripts ./scripts 

EXPOSE 80

CMD ["uvicorn", "my_crs.task_server.main:app", "--host", "0.0.0.0", "--port", "80", "--log-level", "info"]
