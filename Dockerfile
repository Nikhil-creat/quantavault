FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ .
COPY docs ./docs
RUN useradd -m app && chown -R app /app
USER app
HEALTHCHECK CMD python -c "import urllib.request as u;u.urlopen('http://localhost:8000/health')"
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000"]
