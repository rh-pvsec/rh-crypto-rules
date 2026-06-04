FROM scratch
ARG version
ARG release

COPY semgrep-rules /rh-crypto-rules/semgrep-rules

LABEL name="rh-crypto-rules" \
    com.redhat.component="rh-crypto-rules" \
    io.k8s.name="rh-crypto-rules" \
    io.k8s.tags="rh-crypto-rules" \
    summary="Overlay custom rules used to scan sources and detect cryptographic algorithms." \
    description="Overlay custom rules used to scan sources and detect cryptographic algorithms." \
    maintainer="exd-guild-security@redhat.com" \
    distribution-scope="public" \
    url="https://gitlab.cee.redhat.com/security-guild/crypto-scanning/rh-crypto-rules" \
    version="20260604" \
    release="1" \
    vendor="Red Hat, Inc."

