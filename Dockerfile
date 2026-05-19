FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer-cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the source code
COPY . .

# Render injects PORT env var; default to 5000 for local use
EXPOSE 5000

CMD ["python", "backend/app.py"]