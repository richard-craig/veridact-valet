FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home valet && mkdir -p /data && chown valet /data
USER valet
ENV VALET_DATA=/data
EXPOSE 8000 8001
CMD ["python", "demo.py"]
