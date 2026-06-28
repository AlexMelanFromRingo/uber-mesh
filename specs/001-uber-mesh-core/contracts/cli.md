# Contract: `uber-mesh` CLI

Single binary. Text-in/text-out; every command supports `--json` for machine output (constitution Principle VI).
Secrets never appear in any output.

```
uber-mesh <COMMAND> [--config <path>] [--data-dir <path>] [--json] [-v|-vv]

Commands:
  init        Generate + persist a node identity and a default config.toml.
              Prints the PeerId. Refuses to overwrite an existing identity unless --force.
  run         Start the node: load identity+config, bind listeners, join the mesh,
              run discovery/gossip/NAT, health-check + rotate transports.
                --profile <open|moderate|aggressive|shutdown>   (overrides config)
                --listen <multiaddr>...                         (repeatable)
                --bootstrap <multiaddr>...                      (repeatable)
  status      Query a running node (peers, active transports, reachability, recent
              rotation/health events) in human or --json form.
  peer        Subcommands: list | add <multiaddr> | ban <peer_id>.
  keys        Subcommands: show (PeerId + public key only) | rotate-session.
```

## Exit codes

`0` success · `1` generic error · `2` usage error · `3` config/identity error · `4` no reachable transport.

## `status --json` schema (stable)

```json
{
  "peer_id": "b3:…",
  "uptime_s": 0,
  "profile": "aggressive",
  "reachability": "private|public|relayed|unknown",
  "transports": [{"kind": "obfs-tcp", "state": "healthy", "peers": 0}],
  "peers": {"connected": 0, "known": 0},
  "events": [{"t": 0, "kind": "rotation", "detail": "obfs-tcp→quic blocked, stayed obfs-tcp"}]
}
```

No field ever contains private key material or session secrets.
