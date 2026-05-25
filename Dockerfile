FROM python:3.12-slim

# Install system dependencies including nmap
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server
COPY main.py .

# Expose port (for HTTP transport if needed)
EXPOSE 8000

# Run with stdio transport for MCP
CMD ["python", "main.py"]