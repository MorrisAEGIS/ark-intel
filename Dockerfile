FROM python:3.12.11-slim-bookworm@sha256:9bb659dc6d5218917236f3711e866a5634bb4c2f208de9d4533aa4863f57c1d3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ARK_INTEL_HOST=0.0.0.0 \
    ARK_INTEL_PORT=7010 \
    ARK_INTEL_DATABASE_PATH=/var/lib/ark-intel/ark-intel.sqlite3

RUN groupadd --gid 10001 arkintel \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin arkintel \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/ark-intel

WORKDIR /app
COPY pyproject.toml requirements.lock README.md LICENSE ./
COPY arkintel ./arkintel
RUN python -m pip install --no-cache-dir -r requirements.lock \
    && python -m pip install --no-cache-dir --no-deps .

USER 10001:10001
EXPOSE 7010
ENTRYPOINT ["python", "-m", "arkintel"]
