# Contract: `uber-mesh` CLI

Single binary. Text-in/text-out; every command supports `--json` for machine output (constitution Principle VI).
Secrets never appear in any output.

```
uber-mesh <COMMAND> [--config <path>] [--data-dir <path>] [--json] [-v|-vv]

Commands:
  init        Generate + persist a node identity and a default config.toml.
              Mines the one-time identity proof-of-work (MIN_SENDER_POW_BITS = 24; progress on an
              interactive stderr) and stores it in identity.pow.
              Prints the PeerId and PoW. Refuses to overwrite an existing identity unless --force.
  run         Start the node: load identity+config, bind listeners, join the mesh,
              run discovery/gossip/NAT, health-check + rotate transports.
                --profile <open|moderate|aggressive|shutdown>   (overrides config; unknown ⇒ error)
                --listen <multiaddr>...                         (repeatable)
                --bootstrap <multiaddr>...                      (repeatable)
                --psk-file <path>                               (obfs PSK, hex; see "Secrets")
                --psk <hex>                                     (DEPRECATED: visible in `ps`)
  mesh        Run the libp2p gossip overlay over the obfs carrier.
                --listen <multiaddr> --bootstrap <multiaddr>... --topic <name>
                --topic-key-file <path>                         (seals --topic end to end; see "Secrets")
                --psk-file <path> | --psk <hex> (deprecated)
              Prints whether the topic is "sealed" or "PUBLIC" at startup. Sealed messages print as
              `[topic sealed] …`; a sealed blob announcement is fetched from its publisher and decrypted.
                --metrics-addr <PORT|IP:PORT|off>               (opt-in /metrics; default off)
  status      Query a running node (peers, active transports, reachability, recent
              rotation/health events) in human or --json form.
  peer        Subcommands: list | add <multiaddr> | ban <peer_id>.
  keys        Subcommands: show (PeerId + public key + identity PoW bits; no secrets) | rotate-session |
              new-topic-key --out <path> (fresh random 32-byte topic key, hex, written to a NEW 0600 file;
              never printed).
              `keys show --json` → {"peer_id","public_key","pow_nonce","pow_bits","pow_min_bits"}
              (pow_nonce/pow_bits are null if identity.pow is missing or below the minimum).
```

## Secrets

- The obfs PSK override is resolved as `--psk-file` > `--psk` (deprecated, warns) > `UMESH_PSK` env >
  `config.toml`. `--psk` and `--psk-file` are mutually exclusive. Secrets must not be passed on argv.
- **Sealed-topic key** (end-to-end payload confidentiality, message-wire.md v3) for the `mesh --topic`
  topic: `--topic-key-file` > `UMESH_TOPIC_KEY` env (hex) > `config.toml` `[topic_keys]` entry for that
  topic > none. With no key the topic is **public**: every peer that forwards its messages can read them.
  There is no argv form. `[topic_keys]` maps topic name → hex key:

  ```toml
  [topic_keys]
  "uber-mesh/ops" = "<64 hex chars>"
  ```

  A `config.toml` holding topic keys must be `0600`: a group/world-accessible one is refused on load
  (`chmod 600`); a group/world-readable `--topic-key-file` is warned about. Malformed keys are errors that
  never echo the value. Keys are zeroized after use and never logged.
- `status` lists sealed topic **names** only (`"sealed_topics": [...]` in `--json`); `keys` never prints a
  topic key or PSK.
- Identity PoW: `identity.pow` (public nonce, `0600`, written atomically, never through a symlink) sits
  next to `identity.key`. It is re-verified against the key on every load; if it is missing, malformed,
  for another key or below the minimum (e.g. a keystore from before 0.10), `mesh` mines and persists a
  new one before joining (the key file itself is never rewritten).
- `init` creates the data dir `0700` and `identity.key` / `config.toml` `0600` (atomic create, never through
  a symlink); loading the identity through a symlink is refused.
- `config.toml` `profile` must be one of `open|moderate|aggressive|shutdown` (case-insensitive); an
  unknown value is a config error, never a silent fallback.

## Metrics (`mesh` only)

`/metrics` (Prometheus text format) is **disabled by default**. Enable with `--metrics-addr` or
`UMESH_METRICS_ADDR`: a bare `PORT` binds `127.0.0.1:PORT`; `IP:PORT` binds that address (a non-loopback
bind logs a warning — the endpoint is unauthenticated and identifies the node). The legacy `METRICS_PORT`
env var is deprecated and binds loopback only. Only `GET /metrics` is answered (other paths ⇒ empty 404);
limits: 5 s header-read timeout, 8 KiB request head, 8 concurrent connections (excess closed).

## Exit codes

`0` success · `1` generic error · `2` usage error · `3` config/identity error · `4` no reachable transport.

## `status --json` schema (stable)

```json
{
  "peer_id": "b3:…",
  "uptime_s": 0,
  "profile": "aggressive",
  "sealed_topics": ["uber-mesh/ops"],
  "reachability": "private|public|relayed|unknown",
  "transports": [{"kind": "obfs-tcp", "state": "healthy", "peers": 0}],
  "peers": {"connected": 0, "known": 0},
  "events": [{"t": 0, "kind": "rotation", "detail": "obfs-tcp→quic blocked, stayed obfs-tcp"}]
}
```

No field ever contains private key material or session secrets.
