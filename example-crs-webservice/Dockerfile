
FROM python:3.11-slim

WORKDIR /app
# Copy the whole app (including aixcc/* and crs-multilang/*)
COPY . /app

# (Optional) if crs-multilang has extra deps:
# COPY crs-multilang/requirements.txt /app/crs-multilang/requirements.txt
# RUN pip install --no-cache-dir -r /app/crs-multilang/requirements.txt

# Existing install lines...
RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 8000
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000"]
