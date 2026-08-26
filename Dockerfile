#Starts with an official, lightweight Debian Linux image pre-packaged with Python 3.11.
FROM python:3.11-slim 

WORKDIR /SECURITY_PROJECT

# System deps some Python packages need to build wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY documents/ ./documents/

#Ensures Python prints terminal logs instantly to your screen without buffering
ENV PYTHONUNBUFFERED=1

#WORKDIR /SECURITY_PROJECT/src

EXPOSE 8501

# Healthcheck so `docker compose ps` shows real status, not just "running"
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

#CMD ["streamlit", "run", "src/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"] because it is causing a loop while checking for torchvision
CMD ["streamlit", "run", "src/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.fileWatcherType=none"]