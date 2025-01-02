FROM python:3.9-slim

# Copy requirements and install
COPY requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Copy script
COPY main.py /app/main.py

# Run the script
CMD ["python", "main.py"]
