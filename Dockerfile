FROM python:3.7
LABEL maintainer="Blocknet"
RUN apt-get update
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5000
ENTRYPOINT [ "python" ]
CMD [ "plugin-adapter.py" ]
