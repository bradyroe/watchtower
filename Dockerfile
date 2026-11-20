# Watchtower on a small Linux server (EC2). Windows and Tailscale collectors read the PC they
# run on, so they are left out here; see README "Moving to AWS".
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 watchtower && mkdir /data && chown watchtower /data
COPY . .
USER watchtower
ENV WATCHTOWER_DATA=/data \
    WATCHTOWER_BIND=0.0.0.0 \
    WATCHTOWER_COLLECTORS=cloudtrail,posture,s3logs \
    WATCHTOWER_AWS_PROFILE= \
    WATCHTOWER_SECURE_COOKIE=1
EXPOSE 8778
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8778/api/health')"
CMD ["python", "app.py"]
