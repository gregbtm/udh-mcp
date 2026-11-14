FROM python:3.12-slim

LABEL org.opencontainers.image.title="UDH MCP"
LABEL org.opencontainers.image.description="Standalone MCP server for matrix-homelab's Universal Document Hub"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt

COPY src/ ./src/

RUN groupadd -r udhmcp && useradd -r -g udhmcp udhmcp \
    && chown -R udhmcp:udhmcp /app
USER udhmcp

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os, socket; s=socket.create_connection(('127.0.0.1', int(os.getenv('UDH_MCP_PORT', '8090'))), 3); s.close()" || exit 1

CMD ["python", "src/server.py"]
