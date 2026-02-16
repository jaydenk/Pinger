FROM python:3.13-alpine

RUN apk add --no-cache iputils

WORKDIR /app

COPY pinger.py .

CMD ["python", "-u", "pinger.py"]
