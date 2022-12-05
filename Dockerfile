FROM alpine:latest

# the nonprivileged user to start entrypoint with (will be replaced with a random userid at runtime)
ENV RUNTIMEUSER=1001
ENV TZ Europe/Berlin
ENV apiPort 8080

EXPOSE 8080

USER root

COPY ./bin/tado-api-proxy.linux /tado-api-proxy
RUN chmod +x tado-api-proxy

USER ${RUNTIMEUSER}

ENTRYPOINT ["/tado-api-proxy"]