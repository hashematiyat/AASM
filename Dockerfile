FROM python:3.12-slim

LABEL org.opencontainers.image.title="AASM — AI Attack Surface Mapper"
LABEL org.opencontainers.image.description="Enterprise CLI for AI infrastructure security"
LABEL org.opencontainers.image.source="https://github.com/aasm-project/aasm"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 aasm
WORKDIR /home/aasm

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir -e ".[dev]" || true

# Copy source
COPY aasm/ ./aasm/
COPY config/ ./config/

# Install the package
RUN pip install --no-cache-dir -e .

# Switch to non-root
USER aasm

# Create output directory
RUN mkdir -p /home/aasm/aasm_reports

ENTRYPOINT ["aasm"]
CMD ["--help"]

# Usage:
#   docker build -t aasm .
#   docker run --rm -it aasm scan 192.168.1.0/24
#   docker run --rm -it -v $(pwd)/reports:/home/aasm/aasm_reports aasm scan 10.0.0.0/24 -o /home/aasm/aasm_reports
