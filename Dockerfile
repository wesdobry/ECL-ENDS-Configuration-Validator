# Build stage
FROM python:3.13 AS builder

# Set the working directory in the container
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables to avoid Python bytecode and buffering
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Copy the requirements file and install dependencies into /app/deps
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/deps -r requirements.txt

# Runtime stage
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Copy the application code
COPY . /app

# Copy the dependencies from the builder stage
COPY --from=builder /app/deps /usr/local/lib/python3.13/site-packages

# Create the app user and set permissions
RUN addgroup --system app && adduser --system --group app \
    && chown -R app:app /app

# Switch to the app user
USER app

# Expose the port the app runs on
EXPOSE 5000

# Define environment variables
ENV NAME ecl-ends-configuration-validator

# Command to run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
