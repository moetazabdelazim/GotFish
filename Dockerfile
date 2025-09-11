# Use official Python 3.11 image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY . .

# Expose port 8080 (Cloud Run expects this)
EXPOSE 8080

# Run Flask app with host=0.0.0.0 so it's reachable
CMD ["python", "app.py"]
