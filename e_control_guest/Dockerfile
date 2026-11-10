ARG BUILD_FROM
FROM ${BUILD_FROM}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ECONTROL_GUEST_DATA_DIR=/data

COPY requirements.txt /tmp/requirements.txt
RUN apk add --no-cache --virtual .python-build-deps build-base \
    && pip3 install --no-cache-dir -r /tmp/requirements.txt \
    && apk del .python-build-deps

COPY app /opt/e-control-guest/app
COPY rootfs /
WORKDIR /opt/e-control-guest

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8099/health >/dev/null || exit 1
