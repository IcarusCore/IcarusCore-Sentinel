# Optimized Dockerfile for Unraid deployment
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    PORT=5000

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory and data directory
WORKDIR /app
RUN mkdir -p /app/data /app/logs

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create volume mount points for Unraid
VOLUME ["/app/data", "/app/logs"]

# Ensure proper permissions for Unraid (99:100 is nobody:users)
RUN chown -R 99:100 /app && \
    chmod -R 755 /app && \
    chmod -R 777 /app/data /app/logs

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/stats || exit 1

# Create entrypoint script
RUN echo '#!/bin/sh\n\
echo "Starting Threat Intelligence Dashboard..."\n\
echo "Checking environment variables..."\n\
echo "OTX_API_KEY: ${OTX_API_KEY:+[SET]${OTX_API_KEY:0:10}...}${OTX_API_KEY:-[NOT SET]}"\n\
echo "Data directory: /app/data"\n\
echo "Logs directory: /app/logs"\n\
\n\
# Initialize data if not exists\n\
if [ ! -f /app/data/threats.json ]; then\n\
    echo "Initializing threat data..."\n\
    python initialize_data.py\n\
fi\n\
\n\
# Start the application\n\
echo "Starting Flask application on port ${PORT}..."\n\
python app.py\n\
' > /app/start.sh && chmod +x /app/start.sh

# Set user to nobody (Unraid standard)
USER 99:100

# Use the entrypoint script
ENTRYPOINT ["/app/start.sh"]