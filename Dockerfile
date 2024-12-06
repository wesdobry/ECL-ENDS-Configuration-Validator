# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# create the app user
RUN addgroup --system app && adduser --system --group app

# chown all the files to the app user
RUN chown -R app:app /app

# change to the app user
USER app

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV NAME ecl-ends-configuration-validator

# Run app.py when the container launches
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
