FROM golang:1.22

WORKDIR /app

RUN git clone https://github.com/johanix/dns.git

COPY . tdns

RUN cd tdns && make

ENTRYPOINT /app/tdns/tdnsd/tdnsd
