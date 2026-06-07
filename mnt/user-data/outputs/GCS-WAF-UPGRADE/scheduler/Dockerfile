FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget cron gzip logrotate \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app
COPY *.py   /app/
COPY crontab /etc/cron.d/gcs-waf-cron

# Cron needs correct permissions
RUN chmod 0644 /etc/cron.d/gcs-waf-cron \
    && crontab /etc/cron.d/gcs-waf-cron \
    && touch /var/log/cron.log

CMD ["sh", "-c", "cron && tail -f /var/log/cron.log"]
