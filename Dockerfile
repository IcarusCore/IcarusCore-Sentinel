# Optimized Dockerfile for Unraid manual deployment
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

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data and logs directories
RUN mkdir -p /app/data /app/logs

# Ensure proper permissions for Unraid (99:100 is nobody:users)
RUN chown -R 99:100 /app && \
    chmod -R 755 /app && \
    chmod -R 777 /app/data /app/logs

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/stats || exit 1

# Create startup script - using simple sh syntax for compatibility
RUN echo '#!/bin/sh\n\
echo "========================================"\n\
echo "Threat Intelligence Dashboard Starting"\n\
echo "========================================"\n\
echo "Environment Configuration:"\n\
echo "  Flask Env: $FLASK_ENV"\n\
echo "  Port: $PORT"\n\
echo "  Data Dir: /app/data"\n\
echo "  Logs Dir: /app/logs"\n\
echo "  Timezone: ${TZ:-UTC}"\n\
echo ""\n\
echo "API Keys Status:"\n\
if [ -z "$OTX_API_KEY" ]; then\n\
    echo "  OTX API: [NOT SET]"\n\
else\n\
    echo "  OTX API: [CONFIGURED]"\n\
fi\n\
echo "========================================"\n\
\n\
# Initialize data if not exists\n\
if [ ! -f /app/data/threats.json ]; then\n\
    echo "First run detected - initializing data..."\n\
    python initialize_data.py\n\
    echo "Initial data created successfully"\n\
fi\n\
\n\
# Start the application\n\
echo "Starting Flask application..."\n\
echo "Access the dashboard at: http://[YOUR-IP]:$PORT"\n\
echo "========================================"\n\
python app.py\n\
' > /app/start.sh && chmod +x /app/start.sh

# Set user to nobody (Unraid standard)
USER 99:100

# Use the startup script
ENTRYPOINT ["/app/start.sh"]