<img src='https://github.com/nullcryptodev/docs/blob/main/clarity/clarity-wide.png?raw=true'>

# Clarity Daemon (`clarityd`)

The Clarity daemon is the process that runs a Clarity node. It listens
for peers, participates in consensus (if configured as a validator),
serves JSON-RPC, and exposes a Prometheus-compatible metrics endpoint.

This guide is organised by *who you are*:

- **Just running a node** — you want to sync the chain, serve RPC to a
  local application, and otherwise stay out of the way.
- **Running a validator** — you want to produce blocks, earn rewards,
  and manage a consensus signing key.
- **Operating at scale** — you run several nodes, or one node under a
  process supervisor, and you want reproducible configuration.

If you only read one section, read the one that matches your role.
Every flag mentioned here is also listed in `clarityd --help`.

Platform support. The daemon's key-file permission checks are implemented with POSIX stat, lstat, and uid/mode semantics. They are enforced on Linux and macOS. On Windows, the daemon builds and runs, but the permission check is currently a no-op — the file is read without the owner/mode validation described in this document. Do not rely on the file permission model for a Windows validator until this is addressed.

---

## Table of contents

- [What the daemon does](#what-the-daemon-does)
- [Installing and running](#installing-and-running)
- [For everyone: running a node](#for-everyone-running-a-node)
  - [The minimum command line](#the-minimum-command-line)
  - [Choosing a network](#choosing-a-network)
  - [Where state lives](#where-state-lives)
  - [The RPC endpoint](#the-rpc-endpoint)
  - [The metrics endpoint](#the-metrics-endpoint)
  - [Logging](#logging)
  - [P2P](#p2p)
- [For validators: producing blocks](#for-validators-producing-blocks)
  - [The two keys](#the-two-keys)
  - [Generating a validator identity](#generating-a-validator-identity)
  - [Passing the consensus key to the daemon](#passing-the-consensus-key-to-the-daemon)
  - [The consensus key file](#the-consensus-key-file)
  - [Running the validator](#running-the-validator)
  - [Stopping cleanly](#stopping-cleanly)
- [For operators: running at scale](#for-operators-running-at-scale)
  - [Port allocation](#port-allocation)
  - [Running under a process supervisor](#running-under-a-process-supervisor)
  - [Backups](#backups)
  - [Monitoring](#monitoring)
- [Diagnostics](#diagnostics)
  - [Printing the resolved config](#printing-the-resolved-config)
  - [Printing the version](#printing-the-version)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [Full flag reference](#full-flag-reference)

---

## What the daemon does

A running `clarityd` process:

1. **Opens the state database** at `<data-dir>/state` (a single MDBX
   file holding both chain and state data).
2. **Applies genesis** on first run, or resumes from the last
   committed block on subsequent runs.
3. **Listens for peers** on `--p2p-port`, authenticates them, and
   relays blocks and transactions.
4. **Runs consensus** if a validator identity was provided
   (`--validator-id` plus a consensus key). A node without a validator
   identity still syncs, still relays, still serves RPC — it just
   doesn't produce or vote on blocks.
5. **Serves JSON-RPC** on `--rpc-port` if enabled.
6. **Serves Prometheus metrics** on `--metrics-port` if enabled.

It is a single binary and a single state file. There is no separate
chain database, no sidecar process, and no external dependency at
runtime.

---

## Installing and running

Build the daemon following the project's [build
instructions](https://github.com/nullcryptodev/Clarity#build). The
result is `src/Apps/Daemon/clarityd`.

Run `clarityd --help` for the full flag list, or
`clarityd --version` for the protocol and chain IDs.

---

## For everyone: running a node

This section covers the minimum to run a syncing, RPC-serving node.
No validator identity is required.

### The minimum command line

```bash
./clarityd --data-dir /var/lib/clarity
```

That starts a node on **regtest** (the default network) with RPC and
metrics enabled on their default ports. For a real network, add
`--network`:

```bash
./clarityd --network mainnet --data-dir /var/lib/clarity
```

### Choosing a network

| Network | Chain ID | Address prefix | Use it for |
|---|---|---|---|
| `mainnet` | `0x434c5254` | `clrty1...` | The public chain |
| `testnet` | `0x434c5454` | `tclrty1...` | Public testing |
| `regtest` | `0x434c5247` | `rclrty1...` | Local development (default) |

```bash
--network mainnet
```

The network is fixed for the life of a data directory. Switching
`--network` on an existing `--data-dir` will fail genesis validation,
because the genesis block hash is different per network. Use a
separate `--data-dir` for each network.

### Where state lives

`--data-dir` is the directory that holds the MDBX state file. The
daemon creates `<data-dir>/state` on first run.

```bash
--data-dir /var/lib/clarity
```

On regtest, if `--data-dir` is omitted, the daemon uses the current
working directory. This is a development convenience so a throwaway
chain can be started with no arguments. On mainnet and testnet,
`--data-dir` is **required** — a production node should be explicit
about where its state lives.

Two flags tune the MDBX map size, which bounds how large the state
and chain databases can grow:

```bash
--state-map-size 17179869184   # 16 GiB (default)
--chain-map-size 17179869184   # 16 GiB (default)
```

The default of 16 GiB is generous for a chain that hasn't launched.
If you know your disk budget, set these to something that fits.

### The RPC endpoint

The JSON-RPC server is **enabled by default**, bound to
`127.0.0.1:9633`.

```bash
--rpc                        # enabled (default)
--no-rpc                     # disabled
--rpc-bind 127.0.0.1          # bind address (default)
--rpc-port 9633               # listen port (default; 0 = auto)
```

**Binding.** The default `127.0.0.1` means the RPC endpoint is only
reachable from the same host. To serve a local application, this is
what you want. To serve a remote application, bind to a specific
interface (`--rpc-bind 10.0.0.5`) rather than `0.0.0.0`, and put a
reverse proxy in front of it. The RPC endpoint has no authentication
for read methods by default; anyone who can reach it can query
balances, blocks, and state roots.

**CORS.** Browser applications on a different origin need CORS:

```bash
--rpc-cors '*'                 # allow any origin (dev)
--rpc-cors 'https://app.example.com,https://staging.example.com'
--rpc-cors ''                  # disabled (default)
```

The default is disabled, which is the safe default. `'*'` is
appropriate for local development and for a public read-only
endpoint; an explicit allowlist is appropriate for a production
application.

**Workers.** The RPC server runs a small pool of worker threads. The
default of 4 is right for a laptop or a small server. `0` means
"auto" (`max(1, min(hardware_concurrency() - 1, 8))`).

```bash
--rpc-workers 8
```

**Admin methods.** A small set of methods (shutdown, config
inspection) require a bearer token. Set one with:

```bash
--rpc-admin-token "$(head -c 32 /dev/urandom | xxd -p -c 32)"
```

An empty token (the default) means admin methods are not registered
at all — requests for them return `MethodNotFound`. This is the right
default for a public node.

**Error verbosity.** By default, internal error text is suppressed in
RPC error responses. For debugging, `--rpc-verbose-errors` includes
it. Do not enable this on a public endpoint; it can leak internal
state.

### The metrics endpoint

The Prometheus-compatible metrics endpoint is **enabled by default**,
bound to `127.0.0.1:9100`.

```bash
--metrics                     # enabled (default)
--no-metrics                  # disabled
--metrics-bind 127.0.0.1       # bind address (default)
--metrics-port 9100            # listen port (default)
```

Scrape it with:

```bash
curl -s http://127.0.0.1:9100/metrics
```

**Port allocation.** Running more than one daemon on a host requires
each to have its own metrics port. The second daemon binds `9101`,
the third `9102`, and so on. The same applies to `--rpc-port`.

**Per-validator metrics.** A block of per-validator time series (stake,
uptime, rewards) is **off by default**. It adds six series per active
validator, which on a large chain is a lot of cardinality for an
operator who only wants to watch their own node. Enable it with:

```bash
--metrics-include-validators
```

**Binding.** As with RPC, the default is loopback. A metrics endpoint
has no authentication at all, so bind it to a private interface (or
keep it on loopback and scrape through an SSH tunnel) rather than
exposing it publicly.

### Logging

Logs go to stderr by default, at level `info`.

```bash
--log-level info               # trace|debug|info|warn|error
--log-file /var/log/clarity.log
--log-consensus                # log consensus state changes
```

`--log-level debug` is useful for diagnosing a connection or a sync
problem. `trace` is very verbose and intended for short debugging
sessions.

`--log-consensus` logs every consensus state transition (round
advance, lock set, commit). It's what you want when you're trying to
understand why a validator is or isn't committing, and it's noise the
rest of the time.

### P2P

The peer-to-peer listener is enabled by default. Set a port with:

```bash
--p2p-port 22001
```

`0` means "don't listen" — the node will still make outbound
connections but won't accept inbound ones. This is useful for a node
behind a restrictive firewall that only needs to *pull* blocks.

To connect to a specific peer at startup:

```bash
--seed 192.0.2.10:22000              # repeatable
--seeds 192.0.2.10:22000,192.0.2.11:22000
```

The daemon will also learn peers from the address book it builds over
time, and from peers it connects to. `--seed` is how you bootstrap a
node that has never seen the network.

---

## For validators: producing blocks

A validator is a node with a **validator identity** and a **consensus
signing key**. Validators propose blocks, vote on proposals, and earn
rewards.

### The two keys

Every validator has two keys with independent lifecycles:

| Key | What it does | Where it lives |
|---|---|---|
| **Reward address** | Receives block rewards. A user-facing key, normally backed by a mnemonic keystore. | The wallet (`clarity-wallet`) |
| **Consensus key** | Signs proposals, prevotes, precommits, and timeout attestations. | The daemon (`--consensus-key` or `--consensus-key-file`) |

The two are derived from **one BIP-39 mnemonic** at two derivation
paths:

- Reward address: `m/44'/9000'/0'/0'/0'`
- Consensus key: `m/44'/9000'/0'/2'/0'`

One backup covers both. They rotate independently: the reward address
can be changed at any time without affecting consensus participation,
and the consensus key can be rotated without changing where rewards
are paid.

The daemon only ever needs the **consensus** key. It never reads the
reward key or the mnemonic.

### Generating a validator identity

Use the `address` tool to create a keystore and print both keys:

```bash
./src/Apps/Tools/address --new -o my_validator --show-secret
```

The output includes both secrets. Copy the **consensus key secret**
(the one under "validator consensus key") into a file — see [The
consensus key file](#the-consensus-key-file) below.

If you already have a mnemonic:

```bash
./src/Apps/Tools/address --import -o my_validator
./src/Apps/Tools/address --show my_validator --show-secret
```

Keep the keystore. It's how you regenerate the keys if you lose the
plaintext copies, and it's how you sign reward-address transactions.

### Passing the consensus key to the daemon

There are two ways to give the daemon the consensus secret key.

**Option A: `--consensus-key-file <path>` — the production path.**

```bash
--consensus-key-file /etc/clarity/consensus.key
```

The secret lives in a file with restrictive permissions and never
appears in process listings, shell history, or systemd unit files.

**Option B: `--consensus-key <hex>` — the development shortcut.**

```bash
--consensus-key 1f2ffb188fe20fec1932d0ae427ff4dc3947251616ae26a09d677f1a57848af6
```

This passes the secret on the command line, where it is visible to
every process on the host (`ps`, `/proc/<pid>/cmdline`, shell
history). It is a **regtest-only convenience**. On mainnet and
testnet, the daemon refuses to start with this flag and tells you to
use `--consensus-key-file` instead.

Use Option A for anything that isn't a throwaway local chain.

### The consensus key file

> On Windows, file permissions are ACL-based and there is no chmod. The daemon does not enforce an equivalent check on Windows today; see Platform support at the top.

The file contains exactly **64 hexadecimal characters** (32 bytes),
optionally followed by a single trailing newline. Nothing else — no
`0x` prefix, no JSON, no comments.

Create it from the `address` output:

```bash
# paste the consensus secret from `address --show-secret`
printf '%s\n' '1f2ffb188fe20fec1932d0ae427ff4dc3947251616ae26a09d677f1a57848af6' \
  > /etc/clarity/consensus.key
chmod 600 /etc/clarity/consensus.key
```

**The daemon enforces all of the following**, and refuses to start if
any is violated:

- The path exists and is a **regular file** (not a directory, FIFO, or
  device).
- It is **not a symlink**. A symlink can be repointed after the
  permission check, so the daemon rejects them outright.
- It is owned by the daemon's user or by **root**.
- Its mode is **`0600` or stricter** — no group or other access,
  read or write. `0644`, `0640`, and `0660` are all rejected.

If the file is rejected, the error message names the file and the
specific violation, with the fix command where one exists. The most
common one is a fresh file created with the default umask:

```
consensus key error: consensus key file '/etc/clarity/consensus.key'
has mode 0664; must be 0600 or stricter (chmod 600 /etc/clarity/consensus.key)
```

Run the suggested `chmod` and restart.

### Running the validator

A validator needs:

- `--validator-id` — its persistent ID in the validator registry.
- A consensus key — `--consensus-key-file` or (regtest only)
  `--consensus-key`.

```bash
./clarityd \
  --network mainnet \
  --data-dir /var/lib/clarity \
  --validator-id 42 \
  --consensus-key-file /etc/clarity/consensus.key \
  --p2p-port 22000 \
  --rpc --rpc-bind 127.0.0.1 --rpc-port 9633
```

If `--validator-id` is set but neither key source is provided, the
daemon refuses to start:

```
configuration error: node: validator_id set but no consensus key was
provided (use --consensus-key-file or --consensus-key)
```

If a key file is provided but `--validator-id` is 0, the daemon also
refuses to start, because a node with no validator role has nothing to
do with a consensus key:

```
configuration error: node: consensus_key_file was set but validator_id
is 0; a consensus key is only meaningful on a validator
```

**Registering.** Setting `--validator-id` on the daemon does not by
itself make the node a validator on the network. The validator must
first be registered on-chain (a `RegisterValidator` transaction) and
be a member of the active set. The daemon's `--validator-id` must
match the ID assigned at registration. See the wallet documentation
for the registration flow.

**If you were a validator and stopped being one**, the daemon will
still run — it will just sync and relay, and won't produce blocks. It
will produce a warning at startup if `--validator-id` is set but the
validator isn't in the active set.

### Stopping cleanly

Send `SIGINT` (Ctrl+C) or `SIGTERM`. The daemon:

1. Stops accepting new peer connections.
2. Stops the RPC and metrics servers.
3. Flushes state to MDBX and closes the database.
4. Exits with code 0.

The shutdown sequence runs on the P2P event loop thread, which is the
only context where it's safe to take the daemon's locks and join its
threads. A signal handler installed with `std::signal` would be
undefined behavior for the same reason; the daemon uses asio's
`signal_set` instead, which delivers the notification as an event.

Rapid repeated Ctrl+C is handled gracefully — the second one won't
interrupt the shutdown in progress.

If the daemon is killed with `SIGKILL`, MDBX's write-ahead log
recovers the state on the next start. You should not need to do
anything.

---

## For operators: running at scale

This section is for anyone running more than one daemon, or one
daemon under a process supervisor.

### Port allocation

Running two daemons on the same host requires each to have its own
P2P, RPC, and metrics ports. The defaults collide.

| Service | Default | Second daemon |
|---|---|---|
| P2P | `22000` | `22001` |
| RPC | `9633` | `9634` |
| Metrics | `9100` | `9101` |

```bash
# daemon 1
./clarityd --data-dir /var/lib/clarity-1 \
  --p2p-port 22000 --rpc-port 9633 --metrics-port 9100 \
  --validator-id 1 --consensus-key-file /etc/clarity/1.key

# daemon 2
./clarityd --data-dir /var/lib/clarity-2 \
  --p2p-port 22001 --rpc-port 9634 --metrics-port 9101 \
  --validator-id 2 --consensus-key-file /etc/clarity/2.key \
  --seed 127.0.0.1:22000
```

Use a different `--data-dir` for each daemon. A single `--data-dir`
shared by two daemons will corrupt the MDBX file; MDBX does not
support two writers.

### Running under a process supervisor

The daemon is a foreground process that logs to stderr by default,
which is exactly what a process supervisor wants. A minimal systemd
unit:

```ini
[Unit]
Description=Clarity node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=clarity
Group=clarity
ExecStart=/usr/local/bin/clarityd \
  --network mainnet \
  --data-dir /var/lib/clarity \
  --validator-id 42 \
  --consensus-key-file /etc/clarity/consensus.key \
  --p2p-port 22000 \
  --rpc --rpc-bind 127.0.0.1 --rpc-port 9633 \
  --metrics-bind 127.0.0.1 --metrics-port 9100 \
  --log-level info
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/clarity
ReadOnlyPaths=/etc/clarity/consensus.key

[Install]
WantedBy=multi-user.target
```

Notes:

- `User=clarity` and `Group=clarity` — the consensus key file must be
  owned by `clarity` (or root) and mode `0600` or stricter.
- `ReadOnlyPaths=/etc/clarity/consensus.key` — makes the key file
  read-only to the daemon, which is stricter than `0600` and still
  passes the mode check. If you prefer, `0400` on the file itself
  achieves the same thing without the unit directive.
- `Restart=on-failure` — the daemon exits 0 on a clean shutdown (via
  `SIGTERM`) and non-zero on a startup or runtime failure. A clean
  shutdown will not trigger a restart; a crash will.
- `ReadWritePaths=/var/lib/clarity` — the daemon only writes to its
  data directory. This directive is what lets `ProtectSystem=strict`
  coexist with a writable state file.

For a non-validator node, drop the `--validator-id` and
`--consensus-key-file` lines, and drop the `ReadOnlyPaths` directive.

### Backups

Two things are worth backing up:

1. **The keystore.** `my_validator.ks` (or whatever you named it) —
   this is the mnemonic-encrypted file that regenerates both the
   reward address and the consensus key. Without it, and without the
   mnemonic written down separately, you cannot recover the validator
   identity if the host is lost.

2. **The consensus key file.** `/etc/clarity/consensus.key` — this is
   derivable from the keystore, so it's the second-most-important
   thing. If you have the keystore and its password, you can
   regenerate it. If you don't, this file is the only copy.

The **data directory** does not need to be backed up in the sense of
"restorable to the same point." A node that loses its state can resync
from the network. Back it up if you want to avoid a long resync, but
it is not a source of truth.

Do **not** back up the consensus key file and the keystore to the same
location. They should be treated as two independent secrets. A single
backup that contains both is a single point of failure.

### Monitoring

The metrics endpoint is designed to be scraped by Prometheus. A
minimal scrape config:

```yaml
scrape_configs:
  - job_name: clarity
    static_configs:
      - targets: ['127.0.0.1:9100']
    metrics_path: /metrics
    scrape_interval: 15s
```

The metric families an operator cares about most:

| Metric | What it tells you |
|---|---|
| `clrty_height` | Current chain height |
| `clrty_running` | Whether the node is running (1) or not (0) |
| `clrty_uptime_seconds` | How long the process has been up |
| `clrty_p2p_peers_*` | Peer counts by direction and state |
| `clrty_consensus_*` | Consensus height, round, step, timeout count |
| `clrty_active_set_size` | Size of the validator set |
| `clrty_mempool_pending_count` | Transactions waiting to be included |
| `clrty_storage_size_bytes` | On-disk database size |

A validator operator wants alerts on:

- `clrty_running == 0` for more than a minute.
- `clrty_height` not advancing for more than a few blocks.
- `clrty_p2p_peers_established == 0`.
- `clrty_consensus_consecutive_timeouts` climbing steadily.

Per-validator metrics (`--metrics-include-validators`) add stake,
uptime EMA, reward multiplier, cumulative rewards, and pending
unbond height for each active validator.

---

## Diagnostics

### Printing the resolved config

```bash
./clarityd --data-dir /var/lib/clarity --print-config
```

Prints every resolved configuration value — network, chain ID, data
directory, ports, bind addresses, log level, and the *source* of the
consensus key (`file:/etc/clarity/consensus.key`, `argv (regtest
only)`, or `(none)`) — and exits. Nothing is started.

This is the first thing to run when the daemon won't start. It shows
what the daemon thinks it was told, before any of the runtime checks
fire.

Note that `--print-config` runs **before** the consensus key file is
read, so a missing or misconfigured key file will not prevent the
config from printing. This is deliberate: the point of the flag is to
inspect the resolved config, not to validate the secrets.

### Printing the version

```bash
./clarityd --version
```

Prints the daemon version, the protocol version, and the three chain
IDs.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean shutdown (SIGINT, SIGTERM, or admin shutdown RPC) |
| `1` | Startup failure (bad config, bad key file, missing data dir) or runtime fatal error |

A process supervisor should treat any non-zero exit as a failure and
consider restarting. A `0` exit is a deliberate stop and should not
be restarted automatically.

---

## Troubleshooting

**`configuration error: node: validator_id set but consensus_secret_key
is null`**

You set `--validator-id` but no key source. Add
`--consensus-key-file <path>` (production) or `--consensus-key <hex>`
(regtest only).

**`configuration error: node: consensus_key_file and
consensus_secret_key are mutually exclusive`**

You set both `--consensus-key-file` and `--consensus-key`. Pick one.
If you're not sure which you set, `--print-config` will tell you.

**`consensus key error: consensus key file '...' has mode 0664; must
be 0600 or stricter`**

The key file is readable by group or other. Run the `chmod 600`
command in the error message.

**`consensus key error: consensus key file '...' is a symlink`**

The path is a symlink. Use the real path, or copy the file to a
regular location and pass that. The daemon rejects symlinks because
they can be repointed after the permission check.

**`consensus key error: consensus key file '...' cannot be opened`**

The path doesn't exist or isn't readable by the daemon's user. Check
the path and the file's owner.

**The daemon starts but never produces blocks.**

Check that:

- `--validator-id` matches the validator's registered ID.
- The validator is in the active set (`clrty_getActiveSet` over RPC).
- The consensus key file contains the correct key (the public half
  should match what's in the validator record; `address --show-secret`
  prints the public key alongside the secret).
- The node has peers (`--metrics` shows `clrty_p2p_peers_established`).

**The daemon exits with `configuration error: node: data_dir is
required on mainnet and testnet`.**

You omitted `--data-dir` on a non-regtest network. Set it. Only
regtest defaults to the current working directory.

**The RPC endpoint isn't reachable from another host.**

The default bind address is `127.0.0.1`, which is loopback only. To
serve a remote client, bind to a specific interface
(`--rpc-bind 10.0.0.5`) rather than `0.0.0.0`, and put a reverse
proxy in front of it. The RPC endpoint has no authentication for
read methods; anyone who can reach it can read balances and state.

**Two daemons on one host collide on port.**

Each daemon needs its own P2P, RPC, and metrics ports. See [Port
allocation](#port-allocation).

**The daemon won't start with `--network mainnet` after I ran it on
regtest.**

The network is fixed for the life of a data directory. The genesis
block hash differs per network, and the daemon refuses to apply a
genesis that doesn't match what's already in the database. Use a
separate `--data-dir` for each network.

---

## Full flag reference

```
Network:
  --network <name>           mainnet | testnet | regtest (default: regtest)

Storage:
  --data-dir <path>          Data directory (required on mainnet/testnet;
                             defaults to cwd on regtest)
  --state-map-size <bytes>   State DB map size (default: 16 GiB)
  --chain-map-size <bytes>   Chain DB map size (default: 16 GiB)

P2P:
  --p2p-port <port>          Listen port (0 = don't listen)
  --seed <host:port>         Add a seed peer (repeatable)
  --seeds <list>             Comma-separated seeds

Validator:
  --validator-id <N>         Validator ID (0 = not a validator)
  --consensus-key-file <path>
                             File containing the Ed25519 consensus
                             secret key, 64 hex chars. Must be a
                             regular file, not a symlink, mode 0600
                             or stricter. Production path.
  --consensus-key <hex>      Ed25519 consensus secret key as raw hex.
                             Development convenience for regtest only;
                             rejected on mainnet and testnet. Produce
                             one with `address --show-secret`.

Consensus:
  --max-block-bytes <bytes>  Max block size (default: 262144)
  --max-block-txs <count>    Max txs per block (default: 5000)
  --consensus-poll-ms <ms>   Consensus timer poll (default: 100)

RPC:
  --rpc                      Enable the RPC server (default: on)
  --no-rpc                   Disable the RPC server entirely
  --rpc-bind <addr>          Bind address (default: 127.0.0.1)
  --rpc-port <port>          Listen port (default: 9633; 0 = auto)
  --rpc-workers <n>          Worker threads; 0 = auto (default: 4)
  --rpc-admin-token <hex>    Admin bearer token (>=16 chars)
  --rpc-verbose-errors       Include internal error text in responses
  --rpc-cors <list>          CORS origins (comma-separated) or <*>
                             (default: disabled)

Metrics:
  --metrics                  Enable the metrics endpoint (default: on)
  --no-metrics               Disable the metrics endpoint entirely
  --metrics-bind <addr>      Bind address (default: 127.0.0.1)
  --metrics-port <port>      Listen port (default: 9100)
  --metrics-include-validators
                             Include per-validator metrics (default: off)

Logging:
  --log-level <level>        trace|debug|info|warn|error (default: info)
  --log-file <path>          Write logs to file (default: stderr)
  --log-consensus            Log consensus state changes

Diagnostics:
  --print-config             Print resolved config and exit
  -h, --help                 Show this help
  -v, --version              Show version
```