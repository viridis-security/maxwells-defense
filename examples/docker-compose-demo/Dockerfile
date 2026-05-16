FROM python:3.12-slim

WORKDIR /app
COPY ../../python/ ./maxwells-defense/
RUN pip install --no-cache-dir ./maxwells-defense fastapi uvicorn httpx
COPY demo/ ./demo/

EXPOSE 8000
