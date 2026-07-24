FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements-build.lock requirements.lock requirements-test.lock pyproject.toml ./
RUN python -m venv /build/.venv \
    && /build/.venv/bin/pip install --require-hashes -r requirements-build.lock \
    && mkdir dist
COPY src ./src
RUN /build/.venv/bin/pip wheel --no-build-isolation --no-deps . -w dist

FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock ./
COPY --from=build /build/dist /dist
RUN python -m venv /app/.venv \
    && /app/.venv/bin/pip install --require-hashes --no-deps -r requirements.lock \
    && /app/.venv/bin/pip install --no-deps /dist/*.whl
EXPOSE 8080/tcp 51820/udp
ENTRYPOINT ["/app/.venv/bin/afterglow-wg-agent"]
CMD ["serve", "--require-runtime-mounts"]
