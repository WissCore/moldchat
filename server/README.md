# MoldChat server

Single Go module. The server stores opaque ciphertext blobs addressed by queue ID and routes them to recipients. It does not see senders, recipients, contents, social graphs, or message-timing semantics beyond what is required for delivery.

- [`cmd/moldd/`](cmd/moldd/) — server entry point
- [`internal/`](internal/) — private packages (not importable from outside the module)
- [`api/`](api/) — Protobuf and OpenAPI schemas
