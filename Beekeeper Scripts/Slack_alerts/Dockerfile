FROM python:3.12-slim

# Without this, print() output is buffered and never reaches `docker logs slack-notifier`.
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY slack_notifier.py .
CMD ["python", "slack_notifier.py"]
