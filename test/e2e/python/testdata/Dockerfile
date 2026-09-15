FROM python:3.11-slim

# Create a virtual environment and install a known-vulnerable package.
# requests 2.28.0 has CVE-2023-32681 (proxy auth credential leak),
# fixed in 2.28.2 — a stable, well-known patch-level vulnerability.
RUN python -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir requests==2.28.0
