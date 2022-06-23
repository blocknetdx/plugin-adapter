# docker build --build-arg cores=8 -t atcsecure/daemonwrapper:latest .
FROM python:3.7
LABEL maintainer="atcsecure"
RUN apt-get update
#RUN apt-get install -y build-essential cmake musl-dev gcc g++ libffi-dev libssl-dev python2 python2-dev python3-dev curl libkrb5-dev librocksdb-dev libleveldb-dev libsnappy-dev liblz4-dev \
#    && pip install scrypt x11_hash
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN pip install gunicorn
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5000

# ENTRYPOINT [ "python" ]
# CMD [ "app.py" ]

CMD [ "gunicorn", "-c", "gunicorn.conf", "app:app" ]
