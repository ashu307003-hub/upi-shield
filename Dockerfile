FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
    && rm -rf /var/lib/apt/lists/*
RUN python -m playwright install --with-deps chromium

COPY backend/ ./backend/
COPY brands/ ./brands/
COPY data/seeds.txt ./data/seeds.txt

RUN mkdir -p data/captures data/evidence data/reports data/discovered data/private_ids

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
