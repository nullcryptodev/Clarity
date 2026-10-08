# Setup Regtest

> Running a two-validator regtest network

This guide walks through starting a local Clarity network with two seed validators. It's intended for development and testing — nothing here is appropriate for a production validator.

## Prerequisites

1. A cloned copy of the Clarity repository
2. A working build of Clarity (see the main README for build instructions)
3. Two terminals
4. `curl` (optional, for verifying the RPC is up)

## Background: what you're setting up

Clarity's genesis block declares two **seed validators**. Each seed is defined by two things:

- A **reward address** per network (mainnet, testnet, regtest), which receives block rewards
- A **consensus public key**, which is the validator's identity for signing proposals and votes

Both come from a single BIP-39 mnemonic, derived at different paths. The consensus key is identical across all three networks because it carries no network prefix; the reward address differs per network because it's encoded with a network-specific prefix.

For the local network to produce blocks, the daemons you run must sign with the **secret key whose public half matches what genesis declares**. If they don't, every proposal fails signature verification and the chain stalls at height 1. Most of the steps below exist to make sure that match is correct.

## Step 1 — Create two wallets

Build Clarity first, then change into the built tools directory:

```
cd Clarity/build/src/Apps/Tools
```

Create two regtest wallets. Each command generates a fresh mnemonic, derives both keys, and writes an encrypted keystore:

```
./address --new -o regaddr1 --network regtest
./address --new -o regaddr2 --network regtest
```

You'll be prompted for a password twice per wallet. **Write down both mnemonics.** They're the only backup you need — both the reward key and the consensus key are derivable from the mnemonic.

Each command prints, for the wallet it just created:

- The **reward address** for each of the three networks (`clrty...`, `tclrty...`, `rclrty...`)
- The **reward public key** — a 64-character hex string
- The **consensus public key** — a different 64-character hex string

Keep the terminal output for both wallets. You'll need six addresses (three per wallet) and two consensus public keys.

## Step 2 — Extract the consensus secrets

The daemon needs the **secret** half of each consensus key, not the public half. The `address` tool prints secrets on demand:

```
./address --show regaddr1.ks --show-secret
./address --show regaddr2.ks --show-secret
```

Each prints every key in the keystore, including the raw hex secrets. **Copy the consensus secret from each** — the one whose public half matches the consensus public key printed in Step 1. You'll paste these into the daemon launch commands in Step 4.

Do not use the reward key's secret here. The reward key and the consensus key are different keys, and the daemon needs the consensus one.

## Step 3 — Update the genesis configuration

Open `Clarity/include/GlobalConfig.h`. This file declares the seed validators, along with other protocol constants.

Replace the existing seed values with the ones you just generated:

- `SEED_NODE` — the consensus public key from wallet 1
- `SEED_NODE_TWO` — the consensus public key from wallet 2
- `SEED_ADDRESS_MAINNET`, `SEED_ADDRESS_TESTNET`, `SEED_ADDRESS_REGTEST` — the three reward addresses from wallet 1
- `SEED_ADDRESS_TWO_MAINNET`, `SEED_ADDRESS_TWO_TESTNET`, `SEED_ADDRESS_TWO_REGTEST` — the three reward addresses from wallet 2

The consensus public keys are 64-character hex strings. The addresses are bech32m strings starting with the network prefix. Copy them exactly.

## Step 4 — Rebuild Clarity

The seed public keys are baked into the genesis block, and the genesis block's hash is pinned per network. Changing the seed keys changes the genesis hash. You must rebuild for the new values to take effect:

```
cd Clarity/build
make
```

Note: if you're starting from a fresh clone or have changed genesis structure, you may also need to regenerate the pinned genesis hashes. There's a tool for this at `build/src/Apps/Tools/genesis_hash`. It computes the current genesis hash for each network. If the computed hashes don't match the pinned values in `GlobalConfig.h`, update the pinned values to the computed ones — otherwise nodes will refuse to start with a "genesis mismatch" error.

## Step 5 — Launch the two daemons

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
  --consensus-key <wallet-1-consensus-secret> \
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
  --consensus-key <wallet-2-consensus-secret> \
  --p2p-port 22002 \
  --seed 127.0.0.1:22001 \
  --rpc \
  --rpc-bind 127.0.0.1 \
  --rpc-port 9634 \
  --rpc-cors '*'
```

Replace `<wallet-N-consensus-secret>` with the actual secret from Step 2. The `--rpc-cors '*'` flag allows browser-based clients (like a block explorer) to reach the RPC; omit it if you only need shell access.

Start validator 1 first. Its RPC binds to port 9633. Start validator 2 second — it connects to validator 1 at `127.0.0.1:22001` and binds its own RPC to 9634.

## Step 6 — Verify the network is producing blocks

Give it a few seconds, then query validator 1's RPC:

```
curl -s -X POST http://127.0.0.1:9633/rpc \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"blockNumber","params":{}}'
```

You should see a `height` field that increases over time. Query it again a few seconds later and compare. If the height is growing, consensus is working.

If the height stays at `0x1`, consensus is stalled. Check the daemon logs for `validateProposal: signature verification failed`. If you see that, the consensus key the daemon is using doesn't match what genesis declares. Re-check:

- Did you paste the **consensus** public key into `SEED_NODE` / `SEED_NODE_TWO`, or did you accidentally paste the reward public key?
- Did you pass the **consensus secret** to `--consensus-key`, or the reward secret?
- Did you rebuild after editing `GlobalConfig.h`?

The three most common failure modes are all variations of the same mistake: mixing up the reward key and the consensus key. They're both 64-character hex strings, they both come from the same mnemonic, and the `address` tool prints both. Read the labels carefully.

## Optional — Reset the chain

The data directories (`test` and `test2`) accumulate state. To start from genesis, delete them and relaunch:

```
rm -rf test test2
```

The daemons will apply genesis on the next start. Note that deleting the data directories doesn't change anything about the keys — you can reuse the same wallets and the same `--consensus-key` values.
