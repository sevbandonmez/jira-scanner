FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY jira-scanner.py .

# Create output directory
RUN mkdir -p output

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Create non-root user for security
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Expose volume for output
VOLUME ["/app/output"]

# Set entrypoint
ENTRYPOINT ["python3", "jira-scanner.py"]

# Default command (can be overridden)
CMD ["--help"]
