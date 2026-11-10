# PLANTED FINDINGS (main branch): end-of-life base image, root user, no healthcheck.
FROM python:3.8-slim-buster
WORKDIR /app
COPY target-app/requirements.txt .
RUN pip install -r requirements.txt
COPY target-app/vulnapp/ vulnapp/
ENV APP_HOST=0.0.0.0 APP_PORT=5000 APP_MODE=vulnerable
EXPOSE 5000
CMD ["python", "-m", "vulnapp.app"]
