# Build stage has pip; runtime stage is a minimal Wolfi image with no shell.
FROM cgr.dev/chainguard/python:latest-dev AS build
WORKDIR /app
COPY target-app/requirements.txt .
RUN pip install --no-cache-dir --target /app/deps -r requirements.txt

FROM cgr.dev/chainguard/python:latest
WORKDIR /app
COPY --from=build /app/deps /app/deps
COPY target-app/vulnapp/ vulnapp/
ENV PYTHONPATH=/app/deps APP_HOST=0.0.0.0 APP_PORT=5000 APP_MODE=fixed
USER 65532
EXPOSE 5000
HEALTHCHECK CMD ["python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/')"]
ENTRYPOINT ["python", "-m", "vulnapp.app"]
