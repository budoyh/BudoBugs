FROM python:3.15.0-slim-bookworm@sha256:0e019bbdfb5d9874cb2389f1c2884b64aa2ac97c99960b5bc521cef978c0617d

WORKDIR /app
COPY proxy.py /app/proxy.py
USER 65532:65532
ENTRYPOINT ["python", "/app/proxy.py"]
