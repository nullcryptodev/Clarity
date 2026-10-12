<img src='https://github.com/nullcryptodev/docs/blob/main/clarity/clarity-wide.png?raw=true'>

# Setup Regtest

> Running a two-validator regtest network

This guide walks through starting a local Clarity network with two
seed validators. It's intended for development and testing — nothing
here is appropriate for a production validator. For a production
validator, see [`DAEMON.md`](DAEMON.md).

## Prerequisites

1. A cloned copy of the Clarity repository
2. A working build of Clarity (see the main README for build
   instructions)
3. Two terminals
4. `curl` (optional, for verifying the RPC is up)

The commands in this guide are written for a POSIX shell (Linux,
macOS, or WSL). Where a step differs on Windows, a note calls it out.
See the [Platform notes](#platform-notes) section at the end for a
summary.

## Background: what you're setting up

Clarity's genesis block declares two **seed validators**. Each seed is
defined by two things:

- A **reward address** per network (mainnet, testnet, regtest), which
  receives block rewards
- A **consensus public key**, which is the validator's identity for
  signing proposals and votes

Both come from a single BIP-39 mnemonic, derived at different paths.
The consensus key is identical across all three networks because it
carries no network prefix; the reward address differs per network
because it's encoded with a network-specific prefix.

For the local network to produce blocks, the daemons you run must sign
with the **secret key whose public half matches what genesis
declares**. If they don't, every proposal fails signature
verification and the chain stalls at height 1. Most of the steps below
exist to make sure that match is correct.

## Step 1 — Create two wallets

Build Clarity first, then change into the built tools directory:

```
cd Clarity/build/src/Apps/Tools
```

Create two regtest wallets. Each command generates a fresh mnemonic,
derives both keys, and writes an encrypted keystore:

```
./address --new -o regaddr1 --network regtest
./address --new -o regaddr2 --network regtest
```

You'll be prompted for a password twice per wallet. **Write down both
mnemonics.** They're the only backup you need — both the reward key
and the consensus key are derivable from the mnemonic.

Each command prints, for the wallet it just created:

- The **reward address** for each of the three networks (`clrty...`,
  `tclrty...`, `rclrty...`)
- The **reward public key** — a 64-character hex string
- The **consensus public key** — a different 64-character hex string

Keep the terminal output for both wallets. You'll need six addresses
(three per wallet) and two consensus public keys.

## Step 2 — Extract the consensus secrets

The daemon needs the **secret** half of each consensus key, not the
public half. The `address` tool prints secrets on demand:

```
./address --show regaddr1.ks --show-secret
./address --show regaddr2.ks --show-secret
```

Each prints every key in the keystore, including the raw hex secrets.
**Copy the consensus secret from each** — the one whose public half
matches the consensus public key printed in Step 1. You'll write
these into the key files in Step 3.

Do not use the reward key's secret here. The reward key and the
consensus key are different keys, and the daemon needs the consensus
one.

## Step 3 — Write the consensus key files

The daemon reads each validator's consensus secret from a file, not
from the command line. This is the production path: the secret never
appears in `ps`, shell history, or process listings, and the daemon
checks the file's permissions before reading it.

Create one file per validator, containing the consensus secret from
Step 2 as 64 hex characters, with a single trailing newline:

```
printf '%s\n' '<wallet-1-consensus-secret>' > regaddr1.key
printf '%s\n' '<wallet-2-consensus-secret>' > regaddr2.key
```

Then lock each file down so only the current user can read it:

```
chmod 600 regaddr1.key regaddr2.key
```

The daemon refuses to start if the file is group- or world-readable,
if it's a symlink, if it's not a regular file, or if it's owned by a
user other than the daemon's user or root. The `chmod 600` above is
what satisfies the permission check.

**Windows note.** `chmod` is a POSIX command and doesn't exist on
native Windows. The daemon's key-file permission check is
POSIX-only and is currently a no-op on Windows, so this step is not
enforced there. Restrict the file with an explicit DACL if you're on
Windows:

```powershell
icacls regaddr1.key /inheritance:r /grant:r "$env:USERNAME:(R)"
icacls regaddr2.key /inheritance:r /grant:r "$env:USERNAME:(R)"
```

See the [Platform notes](#platform-notes) section for details.

If you'd rather skip the key file for a throwaway devnet, you can pass
the secret directly with `--consensus-key <hex>` instead. That form is
regtest-only and is rejected on mainnet and testnet. The rest of this
guide uses the file form because it's the one that scales.

## Step 4 — Update the genesis configuration

Open `Clarity/include/GlobalConfig.h`. This file declares the seed
validators, along with other protocol constants.

Replace the existing seed values with the ones you just generated:

- `SEED_NODE` — the consensus public key from wallet 1
- `SEED_NODE_TWO` — the consensus public key from wallet 2
- `SEED_ADDRESS_MAINNET`, `SEED_ADDRESS_TESTNET`, `SEED_ADDRESS_REGTEST`
  — the three reward addresses from wallet 1
- `SEED_ADDRESS_TWO_MAINNET`, `SEED_ADDRESS_TWO_TESTNET`,
  `SEED_ADDRESS_TWO_REGTEST` — the three reward addresses from wallet 2

The consensus public keys are 64-character hex strings. The addresses
are bech32m strings starting with the network prefix. Copy them
exactly.

## Step 5 — Rebuild Clarity

The seed public keys are baked into the genesis block, and the genesis
block's hash is pinned per network. Changing the seed keys changes the
genesis hash. You must rebuild for the new values to take effect:

```
cd Clarity/build
make
```

Note: if you're starting from a fresh clone or have changed genesis
structure, you may also need to regenerate the pinned genesis hashes.
There's a tool for this at `build/src/Apps/Tools/genesis_hash`. It
computes the current genesis hash for each network. If the computed
hashes don't match the pinned values in `GlobalConfig.h`, update the
pinned values to the computed ones — otherwise nodes will refuse to
start with a "genesis mismatch" error.

## Step 6 — Launch the two daemons

Change into the daemon directory:

```
cd Clarity/build/src/Apps/Daemon
```

**Terminal 1 — validator 1:**

```
./clarityd \
  --network regtest \
  --data-dir test \
  --validator-id 1 \
  --consensus-key-file ../Tools/regaddr1.key \
  --p2p-port 22001 \
  --rpc \
  --rpc-bind 127.0.0.1 \
  --rpc-port 9633 \
  --rpc-cors '*'
```

**Terminal 2 — validator 2:**

```
./clarityd \
  --network regtest \
  --data-dir test2 \
  --validator-id 2 \
  --consensus-key-file ../Tools/regaddr2.key \
  --p2p-port 22002 \
  --seed 127.0.0.1:22001 \
  --rpc \
  --rpc-bind 127.0.0.1 \
  --rpc-port 9634 \
  --rpc-cors '*' \
  --metrics-port 9101
```

The key file path is relative to the current directory (the Daemon
directory), so it points back into the Tools directory where you
created the files. An absolute path works too and is what you'd use in
a systemd unit; for a devnet, relative is fine.

The `--rpc-cors '*'` flag allows browser-based clients (like a block
explorer) to reach the RPC; omit it if you only need shell access.

**On `--metrics-port 9101` for validator 2.** The metrics endpoint is
enabled by default on every daemon, bound to `127.0.0.1:9100`. Running
two daemons on one host means the second one can't bind 9100 — the
first already has it. The `--metrics-port 9101` flag moves validator
2's metrics endpoint to a different port. Validator 1 keeps the
default (9100). If you don't want metrics at all on the second daemon,
pass `--no-metrics` instead; the effect on the rest of the setup is
the same.

To scrape either node's metrics:

```
curl -s http://127.0.0.1:9100/metrics   # validator 1
curl -s http://127.0.0.1:9101/metrics   # validator 2
```

Start validator 1 first. Its RPC binds to port 9633 and its metrics to
9100. Start validator 2 second — it connects to validator 1 at
`127.0.0.1:22001`, binds its own RPC to 9634, and its metrics to 9101.

## Step 7 — Verify the network is producing blocks

Give it a few seconds, then query validator 1's RPC:

```
curl -s -X POST http://127.0.0.1:9633/rpc \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"blockNumber","params":{}}'
```

You should see a `height` field that increases over time. Query it
again a few seconds later and compare. If the height is growing,
consensus is working.

If the height stays at `0x1`, consensus is stalled. Check the daemon
logs for `validateProposal: signature verification failed`. If you see
that, the consensus key the daemon is using doesn't match what genesis
declares. Re-check:

- Did you paste the **consensus** public key into `SEED_NODE` /
  `SEED_NODE_TWO`, or did you accidentally paste the reward public
  key?
- Did you write the **consensus secret** into the key file, or the
  reward secret?
- Did you rebuild after editing `GlobalConfig.h`?

The three most common failure modes are all variations of the same
mistake: mixing up the reward key and the consensus key. They're both
64-character hex strings, they both come from the same mnemonic, and
the `address` tool prints both. Read the labels carefully.

If the daemon instead exits immediately with a configuration error,
that's a different class of problem. The two most likely messages
are:

- `consensus key file '...' has mode 0664; must be 0600 or stricter`
  — you skipped or mistyped the `chmod 600` in Step 3.
- `consensus key file '...' cannot be opened` — the path in
  `--consensus-key-file` doesn't resolve from the Daemon directory.
  Check the `../Tools/` prefix.

## Optional — Reset the chain

The data directories (`test` and `test2`) accumulate state. To start
from genesis, stop both daemons and delete the directories:

```
rm -rf test test2
```

On Windows:

```powershell
Remove-Item -Recurse -Force test, test2
```

The daemons will apply genesis on the next start. Note that deleting
the data directories doesn't change anything about the keys — you can
reuse the same wallets, the same key files, and the same
`--consensus-key-file` values.

## Platform notes

This guide is written for a POSIX shell. Two steps differ on Windows:

**`chmod 600` (Step 3).** `chmod` is a POSIX command. On native
Windows, the daemon's key-file permission check is a no-op — the file
is read without the owner and mode validation described in
[`DAEMON.md`](DAEMON.md). Use `icacls` to restrict the file, as shown
in Step 3, and treat the file's protection as your responsibility.
A native ACL check is a future change; until then, prefer a Linux
host if you need the permission model enforced.

**`rm -rf` (Reset section).** Use `Remove-Item -Recurse -Force` in
PowerShell, as shown above.

Everything else — `cd`, the `./address` and `./clarityd` invocations,
and the `curl` commands — is the same. On Windows, replace `./` with
`.\` and `\` line continuations with PowerShell backticks, or run the
commands from a POSIX shell under WSL.