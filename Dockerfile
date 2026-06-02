FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    which nmap && \
    nmap --version

# Install uv
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy dependency files first (better Docker layer caching)
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY server.py .
COPY tools ./tools
COPY utils ./utils

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uv", "run", "server.py"]