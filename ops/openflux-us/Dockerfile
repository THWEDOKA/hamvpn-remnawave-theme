FROM golang:1.26.4-alpine AS build
RUN apk add --no-cache git ca-certificates
ENV GOMAXPROCS=2
WORKDIR /src
RUN git init . && git remote add origin https://github.com/p1neappleXpress/OpenFlux.git \
    && git fetch --depth 1 origin 7835b7155e193242d03c46ea6f3cf2b528aaa685 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 7835b7155e193242d03c46ea6f3cf2b528aaa685
COPY openflux.patch /patches/openflux.patch
RUN git apply --check --recount /patches/openflux.patch \
    && git apply --recount /patches/openflux.patch
COPY exit_policy.go exit_policy_test.go /src/tunnel/
RUN go test -p 2 ./... \
    && CGO_ENABLED=0 go build -p 2 -trimpath -ldflags="-s -w" -o /out/openflux .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/openflux /usr/local/bin/openflux
COPY --from=build /src/LICENSE /src/NOTICE /usr/share/licenses/openflux/
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/openflux"]
CMD ["--exit-node", "--mode", "proxy", "--transport", "vyandex", "--url-file", "/run/secrets/document-url"]
