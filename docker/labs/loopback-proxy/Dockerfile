FROM python:3.14.6-slim-bookworm@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8

WORKDIR /app
COPY proxy.py /app/proxy.py
USER 65532:65532
ENTRYPOINT ["python", "/app/proxy.py"]
