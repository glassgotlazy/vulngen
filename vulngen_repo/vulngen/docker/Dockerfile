FROM python:3.11-slim

LABEL maintainer="Anuansh Tiwari <anuanshtiwari191@gmail.com>"
LABEL description="VulnGen pipeline — containerised environment"

# ---------- System dependencies ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
    cppcheck \
    clang \
    default-jdk \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# ---------- Python dependencies ----------
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------- Copy project ----------
COPY . .
RUN pip install -e . --no-deps

# ---------- Results volume ----------
VOLUME ["/app/results"]

# ---------- Default command ----------
CMD ["python", "scripts/run_pipeline.py", "--help"]
