# Use a base image with Python and Flask installed
FROM python:3.11

# Set the working directory in the container
WORKDIR /app

# Copy the UI code to the container
COPY . /app

# Install required Python packages
RUN pip install -r requirements.txt

# Expose the port the UI will run on
EXPOSE 4102

# Run the Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=4102"]
