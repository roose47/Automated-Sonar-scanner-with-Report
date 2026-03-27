FROM python:3.10-slim
# Install Docker CLI to trigger the scanner containers
RUN apt-get update && apt-get install -y docker.io unzip && apt-get clean
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Create the directory for the shared volume mount
RUN mkdir -p /app/scans
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]