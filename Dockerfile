FROM python:3.12-slim

LABEL org.opencontainers.image.title="UDH MCP"
LABEL org.opencontainers.image.description="Standalone MCP server for matrix-homelab's Universal Document Hub"

WORKDIR /app

COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt

COPY src/ ./src/

RUN groupadd -r udhmcp && useradd -r -g udhmcp udhmcp \
    && chown -R udhmcp:udhmcp /app
USER udhmcp

EXPOSE 8090

CMD ["python", "src/server.py"]
