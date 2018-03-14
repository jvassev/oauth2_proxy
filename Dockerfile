FROM debian:stable-slim

RUN apt-get update -y && apt-get install -y ca-certificates curl

ENTRYPOINT [ "/bin/oauth2_proxy" ]

COPY oauth2_proxy /bin/
