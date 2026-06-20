FROM python:3.11-slim
RUN pip install --no-cache-dir httpx
WORKDIR /app
COPY forwarder.py .
CMD ["python", "forwarder.py"]
