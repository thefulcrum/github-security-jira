# -----------------
FROM composer:2.7.8@sha256:57000529b4609b66beeba3ebdd0ebb68b28be262c30669dfccb31003febb245a AS build-env

COPY . /opt/ghsec-jira/

WORKDIR /opt/ghsec-jira

RUN composer install --prefer-dist --no-dev

# -----------------
FROM php:8.3.7-alpine3.18@sha256:3da837b84db645187ae2f24ca664da3faee7c546f0e8d930950b12d24f0d8fa0

COPY --from=build-env /opt/ghsec-jira/ /opt/ghsec-jira/

ENTRYPOINT ["/opt/ghsec-jira/bin/ghsec-jira", "sync", "-vvv"]
