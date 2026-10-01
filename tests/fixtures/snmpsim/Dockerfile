# tests/fixtures/snmpsim/Dockerfile
# Pinned snmpsim fixture image (M9-S2). The base image digest and the pip
# versions are pinned in docs/phase-1/VERSIONS.md; the integration suite builds
# this image via testcontainers (no floating tags).
#
# `cryptography` is REQUIRED for SNMPv3 USM auth/privacy: pysnmp declares it as
# an optional backend and snmpsim does not declare it at all, so without the
# explicit pin v3 requests fail with authentication/decryption errors (verified
# against snmpsim 1.2.2 + pysnmp 7.1.30).
#
# The engine-built BuildKit frontend is used deliberately (repo convention: no
# `# syntax=` directive pulling a floating external frontend).
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b

RUN pip install --no-cache-dir \
    "snmpsim==1.2.2" \
    "pysmi==2.0.0" \
    "pysnmp==7.1.30" \
    "cryptography==50.0.2"

# Simulation data is bind-mounted at /data by the tests. The responder listens
# on the non-privileged port 1161 inside the container (the test maps it).
EXPOSE 1161/udp

ENTRYPOINT ["snmpsim-command-responder"]
CMD ["--data-dir=/data", "--agent-udpv4-endpoint=0.0.0.0:1161", "--log-level=error"]
