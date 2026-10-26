# FROST channel prototype

This project is a small transport prototype for the channel layer discussed before the FROST DKG integration. It uses TCP, mutual TLS (mTLS), a fixed peer list, persistent full-duplex connections, and length-prefixed application messages.

**This prototype does not implement FROST DKG or echo broadcast.** It tests the channel on its own first. The DKG code should use `Channel::send()` and `Channel::receive()` later. Echo broadcast should remain a separate layer for DKG Part 1.

## What is implemented

- One local process per `NODE_ID`.
- One persistent mTLS connection per peer pair.
- The lexicographically smaller peer ID opens the connection.
- Every process listens for incoming connections.
- The client checks the server certificate against the target peer's DNS SAN.
- The server requires a client certificate signed by the configured CA, then maps its single DNS SAN to a configured peer ID.
- The local certificate SAN must match `NODE_ID`.
- A 4-byte, big-endian length prefix frames each message.
- Incoming frame sizes are checked before allocation.
- The timeout applies to the rest of a frame after its first header byte arrives. A higher-level DKG session timeout is still required to handle a peer that never starts a message.
- A read or write failure on any connection marks the channel as failed. The DKG orchestrator should abort its current session if the channel returns an error.
- `send()` waits until the local writer has written the frame to its TLS stream. It does **not** prove that the remote application has processed the message.

## Run the ten-process Docker test

Requirements: Docker with the Compose plugin and OpenSSL on the host.

From this directory:

```bash
./scripts/generate-certs.sh
docker compose up --build
```

Each process connects to all other processes, sends one test message to each peer, and checks that it receives one valid message from every other peer. The processes then wait briefly and exit. Do not use `--abort-on-container-exit`; let every process finish its test.

To remove the local test certificates and generate a new test CA:

```bash
rm -rf certs
./scripts/generate-certs.sh
```

The script refuses to overwrite an existing CA or keys.

## Run tests on the host

```bash
cargo test
```

The framing tests cover a round trip, an oversized length, and a partial-header timeout.

## Main source files

- `src/channel/mod.rs`: the channel interface (`send`, `receive`, and peer IDs).
- `src/channel/tls_mesh.rs`: TLS setup, peer identity checks, mesh setup, and connection tasks.
- `src/channel/framing.rs`: message framing and size/time checks.
- `src/config.rs`: environment configuration.
- `src/main.rs`: a small all-to-all test application.

## Security limits

This is a local development prototype, not a production-ready transport. The local test CA issues all ten identities. In a real deployment, the certificate issuance process must prevent an unauthorized party from obtaining a certificate with another peer's SAN. The static peer list must also come from a trusted and consistent configuration source. This prototype does not implement certificate revocation, peer re-keying, reconnect-and-resume, DKG session IDs, FROST ID binding, or echo broadcast.
