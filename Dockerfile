# Generated for MCP Standard Container Runtime (Glama / Docker)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies needed for image decoding and runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY nexargio_mcp.py ./

RUN pip install --no-cache-dir .

ENTRYPOINT ["nexargio-mcp"]
