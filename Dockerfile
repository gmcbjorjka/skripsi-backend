# Use Python 3.10 slim image
FROM python:3.10-slim

# Allow logs to immediately appear in Google Cloud logs
ENV PYTHONUNBUFFERED True

# Install system dependencies required by XGBoost (OpenMP runtime)
RUN apt-get update && apt-get install -y \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory in container
WORKDIR /app

# Copy application files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run gunicorn on container startup, binding to the PORT environment variable
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 server:app
