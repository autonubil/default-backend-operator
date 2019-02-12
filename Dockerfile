ARG REPO=github.com/autonubil/default-backend-operator
ARG VERSION=v0.0.0-debug
ARG BUILD_DATE=latest
ARG COMMIT=latest
FROM golang:1.10.2 AS build-env
ARG REPO
LABEL maintainer="carsten.zeumer@autonubil.de"

WORKDIR /usr/local/go/src

COPY app /usr/local/go/src/$REPO/app
COPY pkg /usr/local/go/src/$REPO/pkg
COPY vendor /usr/local/go/src/$REPO/vendor
COPY *.go /usr/local/go/src/$REPO/

WORKDIR /usr/local/go/src/$REPO

RUN pwd && ls -alh

RUN  CGO_ENABLED=0 GOOS=linux go build -ldflags "-X cmd/default-backend-operator.Version=$CI_COMMIT_REF_NAME -X cmd/default-backend-operator.BuildDate=$(date --iso-8601=seconds) -X cmd/default-backend-operator.Commit=$CI_COMMIT_SHA -s" -a -installsuffix cgo  -v -o /bin/default-backend-operator ./default-backend-operator.go


# final stage
FROM gcr.io/distroless/base@sha256:a26dde6863dd8b0417d7060c990abe85c1d2481541568445e82b46de9452cf0c
LABEL maintainer="carsten.zeumer@autonubil.de"

WORKDIR /

COPY --from=build-env /bin/default-backend-operator /default-backend-operator
COPY /configs/static static

EXPOSE 9350

CMD ["/default-backend-operator"]
