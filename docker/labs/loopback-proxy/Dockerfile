FROM python:3.14.8-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83

WORKDIR /app
COPY proxy.py /app/proxy.py
USER 65532:65532
ENTRYPOINT ["python", "/app/proxy.py"]
