FROM python:3.12-slim

WORKDIR /app

# Install only what verify.py needs at runtime.
RUN pip install --no-cache-dir cryptography

# Copy the verifier and entrypoint script.
COPY verify.py .
COPY entrypoint.sh .

# Make entrypoint executable.
RUN chmod +x entrypoint.sh

# Default: text mode. Use --format json or --format none at runtime.
ENTRYPOINT ["./entrypoint.sh"]
