# Multi-stage: build deps in one stage, copy only what runs into the final image.
FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim
# Non-root runtime user
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=builder /install /usr/local
COPY main.py ./
USER appuser
EXPOSE 8000
# Honour the platform's $PORT when present (Render, Railway, Fly, Cloud Run).
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
