FROM python:3.12-slim

WORKDIR /usr/src/app

# Install Chromium & necessary dependencies
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    wget \
    gnupg \
    libgconf-2-4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Set environment variable to avoid redundant chromium download
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

# Copy Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application code
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Run FastAPI API
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]