# Starts with an official, lightweight Debian Linux image pre-packaged with Python 3.11.
FROM python:3.11-slim 

WORKDIR /Security_Project

# System deps some Python packages need to build wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project modules and source folders
COPY src/ ./src/
COPY backend/ ./backend/
COPY documents/ ./documents/
COPY data/ ./data/

# Ensures Python prints terminal logs instantly to your screen without buffering
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Healthcheck targeting the FastAPI docs/root endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/docs')" || exit 1

CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]