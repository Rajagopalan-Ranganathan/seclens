# Stage 1: Builder — includes shell, dnf, pip for installing dependencies
FROM registry.access.redhat.com/hi/python:3.12-builder AS builder

USER 0

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.lock /tmp/requirements.lock
RUN pip3 install --no-cache-dir -r /tmp/requirements.lock

COPY src/ /opt/app/src/
COPY pyproject.toml /opt/app/
COPY frontend/ /opt/app/frontend/

RUN pip3 install --no-cache-dir /opt/app

RUN mkdir -p /opt/app/data && chown 1001:0 /opt/app/data

# Stage 2: Production — distroless, no shell, minimal attack surface
FROM registry.access.redhat.com/hi/python:3.12

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/app/frontend /opt/app/frontend
COPY --from=builder --chown=1001:0 /opt/app/data /opt/app/data

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/app

USER 1001

EXPOSE 8000

ENTRYPOINT ["python3", "-m", "gunicorn", "seclens.main:app", \
            "--bind", "0.0.0.0:8000", \
            "--workers", "2", \
            "--worker-class", "uvicorn.workers.UvicornWorker", \
            "--access-logfile", "-"]
