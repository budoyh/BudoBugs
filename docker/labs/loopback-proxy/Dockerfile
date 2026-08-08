FROM python:3.14.0-slim-bookworm@sha256:d13fa0424035d290decef3d575cea23d1b7d5952cdf429df8f5542c71e961576

WORKDIR /app
COPY proxy.py /app/proxy.py
USER 65532:65532
ENTRYPOINT ["python", "/app/proxy.py"]
