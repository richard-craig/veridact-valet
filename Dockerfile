FROM python:3.15-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt requirements-cloud.txt ./
# CLOUD_EXTRAS=1 adds the Azure Key Vault and AWS KMS clients, for signing keys held in a key service
ARG CLOUD_EXTRAS=""
RUN pip install --no-cache-dir -r requirements.txt && \
    if [ -n "$CLOUD_EXTRAS" ]; then pip install --no-cache-dir -r requirements-cloud.txt; fi
COPY . .
RUN useradd --create-home valet && mkdir -p /data && chown valet /data
USER valet
ENV VALET_DATA=/data
EXPOSE 8000 8001
CMD ["python", "demo.py"]
