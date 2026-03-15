# Sovereign-Sync Dockerfile
# Multi-stage build for optimized production image

FROM python:3.11-slim as builder

# Install system dependencies for PCRE2 and Python packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcre2-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Download and install spaCy model
RUN python -m spacy download en_core_web_sm

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcre2-8-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash sovereign

# Set work directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/sovereign/.local

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs && chown -R sovereign:sovereign /app

# Switch to non-root user
USER sovereign

# Add local bin to PATH
ENV PATH=/home/sovereign/.local/bin:$PATH
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start application
CMD ["python", "main.py"]