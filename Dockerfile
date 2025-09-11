# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements and app files
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port 8080
EXPOSE 8080

# Run Flask app with Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
