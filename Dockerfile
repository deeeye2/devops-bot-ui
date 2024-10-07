# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install any required packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the container
COPY . .

# Expose the port that the Flask app runs on
EXPOSE 4102

# Set the environment variable for Flask
ENV FLASK_APP=app.py

# Run the Flask server
CMD ["flask", "run", "--host=0.0.0.0", "--port=4102"]
