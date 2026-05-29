FROM scratch

COPY semgrep-rules /rh-crypto-rules/semgrep-rules

LABEL name="rh-crypto-rules" \
    summary="Overlay custom rules used to scan sources and detect cryptographic algorithms." \
    description="Overlay custom rules used to scan sources and detect cryptographic algorithms." \
    maintainer="exd-guild-security@redhat.com" \
    vendor="Red Hat, Inc."

