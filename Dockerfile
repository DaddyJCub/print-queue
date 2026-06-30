FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY agent ./agent
COPY device ./device
COPY docs ./docs
# Agent source is served as a tarball by the guided-setup install command.
COPY agent ./agent

ENV DB_PATH=/data/app.db
ENV UPLOAD_DIR=/uploads

EXPOSE 3000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "3000"]
