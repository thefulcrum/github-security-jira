# -----------------
FROM composer:2.7.6@sha256:23beecbb2cf15f2bddeb8115f877896ade09e47cf44ccf341204ed1d947a0f38 AS build-env

COPY . /opt/ghsec-jira/

WORKDIR /opt/ghsec-jira

RUN composer install --prefer-dist --no-dev

# -----------------
FROM php:8.3.6-alpine3.18@sha256:a2d3001213e2a4c5bd411ae187c9e2c7de2b929aa884bfadf0b5a400cfbd52b4

COPY --from=build-env /opt/ghsec-jira/ /opt/ghsec-jira/

ENTRYPOINT ["/opt/ghsec-jira/bin/ghsec-jira", "sync", "-vvv"]
