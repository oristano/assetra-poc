FROM alpine:3.19 AS plugin-downloader
RUN apk add --no-cache curl ca-certificates
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') && \
    mkdir -p /plugin && \
    curl -fsSL \
      "https://github.com/turbot/steampipe-plugin-csv/releases/latest/download/steampipe-plugin-csv.linux.${ARCH}.tar.gz" | \
    tar xz -C /plugin

FROM ghcr.io/turbot/steampipe:latest
COPY --from=plugin-downloader --chown=steampipe:steampipe /plugin/ \
     /home/steampipe/.steampipe/plugins/hub.steampipe.io/plugins/turbot/csv@latest/
CMD ["service", "start", "--foreground", "--database-listen=network", "--database-password=steampipe"]
