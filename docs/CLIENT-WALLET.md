<img src='https://github.com/nullcryptodev/docs/blob/main/clarity/clarity-wide.png?raw=true'>

# Clarity Wallet (`clarity_wallet`)

The Clarity wallet is the interactive client for the CLRTY chain. It
opens a keystore, connects to a node's JSON-RPC endpoint, and gives
you a REPL for the operations a normal user cares about: checking
balances, sending CLRTY, staking, registering as a validator, and
managing fungible and non-fungible tokens.

It is a **client**, not a node. It does not sync the chain, does not
participate in consensus, and does not hold a copy of the state. It
asks a node for everything, and signs transactions locally with a key
that never leaves the keystore file.

This guide is organised by *what you're trying to do*:

- **First-time setup** — install, open a keystore, connect to a node.
- **Everyday use** — balances, transfers, staking.
- **Tokens** — create, mint, burn, and inspect fungible tokens.
- **NFTs** — mint, transfer, and manage collections.
- **Validator operations** — register, update the reward address,
  unregister.

If you only read one section, read the one that matches your goal.
Every command is also listed in the [command reference](#command-reference)
at the end, and `help <command>` in the REPL gives the same text.

---

## Table of contents

- [What the wallet is and isn't](#what-the-wallet-is-and-isnt)
- [First-time setup](#first-time-setup)
  - [Getting the binary](#getting-the-binary)
  - [Connecting to a node](#connecting-to-a-node)
  - [Opening a keystore](#opening-a-keystore)
  - [The startup wizard](#the-startup-wizard)
- [Everyday use](#everyday-use)
  - [Checking a balance](#checking-a-balance)
  - [Sending CLRTY](#sending-clrt)
  - [Sending a non-native token](#sending-a-non-native-token)
  - [Checking a nonce](#checking-a-nonce)
  - [Checking a transaction](#checking-a-transaction)
  - [Claiming staking rewards](#claiming-staking-rewards)
  - [Toggling auto-staking](#toggling-auto-staking)
- [Tokens](#tokens)
  - [Listing tokens](#listing-tokens)
  - [Looking up a token](#looking-up-a-token)
  - [Creating a token](#creating-a-token)
  - [Minting tokens](#minting-tokens)
  - [Burning tokens](#burning-tokens)
  - [Updating a token](#updating-a-token)
  - [What you hold](#what-you-hold)
- [NFTs](#nfts)
  - [The model in one paragraph](#the-model-in-one-paragraph)
  - [Collections](#collections)
  - [Minting an NFT](#minting-an-nft)
  - [Transferring and burning](#transferring-and-burning)
  - [Wrapped NFTs](#wrapped-nfts)
  - [Metadata](#metadata)
  - [Collection reward schedules](#collection-reward-schedules)
- [Validator operations](#validator-operations)
  - [Registering](#registering)
  - [Checking your validator record](#checking-your-validator-record)
  - [Updating the reward address](#updating-the-reward-address)
  - [Unregistering](#unregistering)
- [Advanced topics](#advanced-topics)
  - [Verified balances](#verified-balances)
  - [Working offline](#working-offline)
  - [Session state](#session-state)
- [Troubleshooting](#troubleshooting)
- [Command reference](#command-reference)
- [Platform notes](#platform-notes)

---

## What the wallet is and isn't

**What it is:**

- An interactive REPL that talks to a Clarity node over JSON-RPC.
- A local signer: it holds an encrypted keystore, unlocks it with a
  password, and signs transactions with the key inside.
- A convenience layer for the RPC methods a user actually needs, with
  human-readable output.

**What it isn't:**

- A node. It does not sync, mine, vote, or relay.
- A multi-account manager. One keystore is open at a time; `open` and
  `close` switch between them.
- A hardware-wallet client. The signing key lives in the keystore file,
  in memory only while unlocked.
- A light client. By default it trusts the node it talks to for the
  state root; `balance --verify` (see [Verified
  balances](#verified-balances)) is the exception.

---

## First-time setup

### Getting the binary

Build the project following the main README. The wallet ends up at
`src/Apps/Wallet/clarity_wallet`.

```
./src/Apps/Wallet/clarity_wallet --help
```

### Connecting to a node

The wallet talks to a node over RPC. The default endpoint is
`127.0.0.1:9633`, which is where the daemon listens by default.

You can point it elsewhere on the command line:

```
./clarity_wallet --rpc 192.0.2.10:9633
```

Or from inside the REPL:

```
clrty> connect 192.0.2.10:9633
Connected to 192.0.2.10:9633
```

The wallet does not need a node to start. If the node is unreachable,
the startup wizard offers to continue offline, and you can `connect`
later. Commands that need a node will fail with a clear message.

### Opening a keystore

A keystore is an encrypted JSON file holding your BIP-39 seed. It is
the only thing the wallet needs to sign transactions, and the only
thing you need to back up.

You can create one with the `address` tool:

```
./src/Apps/Tools/address --new -o my_wallet --network mainnet
```

You'll be prompted for a password twice. **Write down the mnemonic** —
it is the only way to recover the keys if the keystore file is lost.

Then open it in the wallet:

```
clrty> open my_wallet.ks
Keystore password:
Unlocked my_wallet.ks (clrty1...) — mainnet
```

Or pass it on the command line to skip the wizard's keystore-selection
step:

```
./clarity_wallet --keystore my_wallet.ks
```

The password is always prompted unless you pass `--password-file`.
There is deliberately no `--password` flag: a password on a command
line is visible to every process on the host, and there is no way to
make that safe.

### The startup wizard

If you don't pass `--keystore`, the wallet runs a short wizard:

1. **Connect to RPC.** Probes the endpoint. If it fails, offers retry,
   a different endpoint, or "continue offline."
2. **Find a keystore.** Scans the current directory for `*.ks` files
   and lists them by address and network. You can pick one, open a
   different path, or skip.
3. **Confirm.** Prints the chosen keystore's path, address, and
   network, and asks you to confirm.
4. **Unlock.** Prompts for the password. On a wrong password, offers
   retry or back to the keystore list.

The wizard is skippable: `--keystore <path>` goes straight to the
unlock prompt, and `--rpc <host:port>` sets the endpoint.

---

## Everyday use

### Checking a balance

```
clrty> balance
1049.78000 CLRTY
```

The default is the native CLRTY balance of the open keystore's
address. To check a different address:

```
clrty> balance clrty1q...
100.00000 CLRTY
```

To see a non-native token balance, use `tokens` (see [What you
hold](#what-you-hold)) or `token show` and the token-specific methods.

### Sending CLRTY

```
clrty> send clrty1q... 10.5 0.001
```

The three arguments are the recipient, the amount, and the fee. All
three are in CLRTY, not atomic units — `10.5` sends ten and a half
CLRTY, and `0.001` pays a fee of one-thousandth of a CLRTY.

The wallet:

1. Fetches the current nonce.
2. Builds and signs the transaction locally.
3. Submits it to the node.

By default the wallet prints the txid and returns to the prompt:

```
Submitted: 0x9a4f...
```

Add `--wait` to poll for confirmation:

```
clrty> send clrty1q... 10.5 0.001 --wait
Submitted: 0x9a4f...
Waiting for confirmation...
Confirmed.
```

`--dry-run` builds and prints the transaction without signing or
submitting it. Useful for checking that the amount and fee are what
you meant.

### Sending a non-native token

Use `--token <id>`:

```
clrty> send clrty1q... 100 0.001 --token 1
```

That sends 100 units of token `1` (in that token's own units — check
the token's `decimals` with `token show` first). The `--token` flag is
accepted only on `send`; every other command that operates on a token
takes the id as a positional argument.

### Checking a nonce

```
clrty> nonce
5
```

The nonce is the number of transactions the account has ever sent.
Every transaction the wallet builds uses the current nonce, so you
almost never need to look at this — but it's useful when a transaction
appears stuck.

### Checking a transaction

```
clrty> status
(using last txid: 0x9a4f...)
Confirmed: success
{ ...receipt JSON... }
```

With no argument, `status` uses the last txid submitted in this
session. With an argument, it checks a specific transaction:

```
clrty> status 0x9a4f...
```

If the transaction is not yet in a block, it prints `Pending`. If it's
in a block but failed, it prints `Confirmed: FAILED` and the receipt,
which carries the `fee_paid` value.

### Claiming staking rewards

```
clrty> claim 0.001
```

Moves pending staking rewards into the account balance. Add `--wait`
to poll for confirmation, and `--dry-run` to inspect without
submitting.

### Toggling auto-staking

```
clrty> stake opt-in 0.001
clrty> stake opt-out 0.001
```

Auto-staking causes the account's balance to be staked automatically
whenever it crosses the network's stake threshold. Staked accounts
earn rewards at epoch boundaries. Opting out does not unstake
immediately — the previously staked amount remains staked until the
epoch processes it.

---

## Tokens

The wallet manages fungible tokens end-to-end: you can create a token,
mint more of it, burn it, update its metadata, and inspect it. The
`token` command family is the entry point.

### Listing tokens

```
clrty> token list
Count: 2
  [0x0] CLRTY — Clarity (decimals=5)
  [0x1] exmpl — example (decimals=0)
```

The native token is always `id 0x0`. Everything else is a user token.

For larger lists, use `--limit` and `--offset`:

```
clrty> token list --limit 100 --offset 0
```

### Looking up a token

```
clrty> token show 1
Token 0x1
  name:        example
  symbol:      exmpl
  decimals:    0
  creator:     clrty1q...
  backing:     unbacked
  max supply:  0x64
  royalty:     0 bps
```

`max supply: 0x64` is 100 in decimal — the token can never have more
than 100 units in circulation. If the field is `0x0`, the token is
uncapped.

`token supply <id>` shows the current supply (as opposed to the cap):

```
clrty> token supply 1
Supply: 1
```

### Creating a token

```
clrty> token create "Example" "EXMPL" 0.01
```

The two positional arguments are the name and symbol. The third is
the fee in CLRTY.

Optional flags tune the token:

| Flag | Default | Meaning |
|---|---|---|
| `--decimals N` | 8 | Decimal places (0..18). Cannot be changed later. |
| `--backing 0\|1` | 0 | 0 = unbacked, 1 = bridged (claim on an external asset). |
| `--max-supply N` | 0 | Maximum supply, in atomic units. 0 means uncapped. |
| `--royalty N` | 0 | Advisory royalty in basis points (0..10000). Not enforced on-chain. |
| `--fingerprint H` | (none) | 32-byte hex content hash. Meaningful only for bridged tokens. |

Example with all the options:

```
clrty> token create "Example" "EXMPL" 0.01 \
         --decimals 6 \
         --max-supply 1000000 \
         --royalty 500
```

That creates a token with six decimals, a maximum supply of 1,000,000
whole units (expressed as `1000000 * 10^6` atomic units — the wallet
takes whole units and multiplies for you), and a 5% advisory royalty.

The wallet submits the transaction and prints the txid. Add `--wait` to
block until confirmation. Once confirmed, `token list` shows the new
token and its id.

### Minting tokens

Only the token's creator can mint. The recipient does not have to be
the creator.

```
clrty> token mint 1 clrty1q... 500 0.01
```

The positional arguments are the token id, the recipient, the amount
in whole token units, and the fee. The amount is subject to the max
supply: minting past the cap fails at the executor with a clear error.

### Burning tokens

Any holder can burn their own tokens. Burning reduces the tracked
supply.

```
clrty> token burn 1 50 0.01
```

The token id, the amount, and the fee.

### Updating a token

Only the token's creator can update a token's name, symbol, or
royalty. The decimals and max supply are fixed.

```
clrty> token update 1 --name "New Name" --symbol "NEW" --royalty 100 0.01
```

Any subset of the three flags may be given; the rest are left
unchanged. At least one must be present.

### What you hold

```
clrty> tokens
Tokens held by clrty1q...:
  [0x0] 104978000 (atomic units)
  [0x1] 500 (atomic units)
```

The list includes the native balance (`0x0`) and every non-native
token the address holds. To check a different address:

```
clrty> tokens clrty1q...
```

---

## NFTs

Clarity's NFTs are first-class state objects, not contracts. Every NFT
is also a token with a supply of one, so `balance` and `send` work on
it without special casing.

### The model in one paragraph

An NFT has an id, an owner, a creator, an optional collection, and
metadata (a URI and/or a content hash). When it's minted, a **shadow
token** is created with the same id and a supply of one. That shadow
token is what the token commands and the DEX see; the NFT-specific
commands are the ones that operate on the ownership and metadata. A
**wrapped** NFT additionally holds an amount of an underlying token in
virtual custody — the custody lives at a derived address, and the NFT
owner can release it by burning the NFT.

### Collections

A collection groups NFTs and can carry a reward schedule. Most real
use cases want one: a collection gives you a name, a symbol, an
optional base URI, and a place to attach per-epoch rewards.

```
clrty> collection create "My Collection" "MYC" 0.01
```

Optional `--uri` sets the base URI that NFTs without their own URI
inherit.

```
clrty> collection list
Count: 1
  [0x1] My Collection (MYC) minted=0

clrty> collection show 1
Collection 0x1
  name:              My Collection
  symbol:            MYC
  creator:           clrty1q...
  base uri:          (none)
  minted count:      0
  created at:        0x7b
  reward schedule:   (none)
```

### Minting an NFT

```
clrty> nft mint - 0.01
```

The `-` means "no collection" — a standalone NFT with no grouping and
no reward schedule. To mint into a collection:

```
clrty> nft mint 1 0.01 --uri "ipfs://Qm..."
```

Optional `--hash` adds a 32-byte content hash alongside (or instead
of) the URI:

```
clrty> nft mint 1 0.01 --hash 0xabc...
```

Both the URI and the hash can be set. The executor enforces a maximum
URI length (currently 256 bytes).

After minting, `nft list` shows the NFT:

```
clrty> nft list
Count: 1
  [0x1] collection=0x1 uri=ipfs://Qm...

clrty> nft show 1
NFT 0x1
  owner:            clrty1q...
  creator:          clrty1q...
  shadow token id:  0x1
  collection:       0x1
  metadata uri:     ipfs://Qm...
  metadata hash:    (none)
  frozen:           no
  accrued owed:     0
  last accrual:     0x7b
  created at:       0x7b
```

### Transferring and burning

```
clrty> nft transfer 1 clrty1q... 0.01
clrty> nft burn 1 0.01
```

Transferring moves ownership and the shadow token balance. Burning
deletes the NFT record and releases any wrapped custody to the current
owner. A burn also decrements the collection's `minted_count`.

### Wrapped NFTs

A wrapped NFT holds an amount of an underlying token. Wrap on mint:

```
clrty> nft wrap 1 100 --collection 1 0.01
```

The positional arguments are the underlying token id, the amount, and
the fee. The wallet takes `100` units of token `1` from your balance
and locks them at the NFT's custody address. `nft show` now displays a
wrapped section:

```
  wrapped:          yes
    underlying:     0x1
    amount:         100
    custody:        clrty1q...
```

To add more underlying later:

```
clrty> nft topup 1 1 50 0.01
```

The arguments are the NFT id, the underlying token id, the amount, and
the fee. For a wrapped NFT the token must match the underlying. For a
standalone NFT, `nft topup` accepts any token as a gift — the custody
is a real balance, but the `wrapped_amount` field stays at zero.

Burning a wrapped NFT releases the full custody to the current owner.

### Metadata

An NFT's URI and hash can be changed after minting, unless the NFT is
frozen. Freezing is one-way.

```
clrty> nft metadata 1 --uri "ipfs://new" 0.01
clrty> nft metadata 1 --freeze 0.01
```

`--freeze` can be combined with `--uri` or `--hash` to set the final
metadata and lock it in the same transaction:

```
clrty> nft metadata 1 --uri "ipfs://final" --freeze 0.01
```

After freezing, further `nft metadata` transactions on the NFT are
rejected by the executor. Transfers and burns are unaffected.

### Collection reward schedules

A collection can carry a reward schedule paid from a pre-funded
escrow. Every NFT in the collection accrues at the collection's rate.

To create a collection with a schedule:

```
clrty> collection create "Rewards" "RWD" \
         --reward-token 1 \
         --reward-rate 100 \
         --escrow 100000 \
         0.01
```

`--reward-token` is the token id paid out (must be a token you hold),
`--reward-rate` is the amount paid per NFT per epoch, and `--escrow`
is the initial funding. The escrow is debited from your balance of the
reward token in the same transaction.

To refill the escrow when it runs low:

```
clrty> collection refill 1 50000 0.01
```

The arguments are the collection id, the amount, and the fee.

Holders claim their accrued rewards with:

```
clrty> nft claim 0.001
```

That settles every NFT reward the caller has accrued into the caller's
`pending_rewards` bucket, which `claim` then moves into the balance.
You can run `claim` on its own; it settles both staking and NFT
rewards.

---

## Validator operations

A validator is a node with a consensus key and an on-chain record. The
wallet manages the record; the daemon runs the node. See
[`DAEMON.md`](DAEMON.md) for the daemon side.

### Registering

Registration requires a node key — the P2P identity the validator's
daemon will use — and a stake. Both are provided by the daemon's
operator; the wallet's job is to put them on chain.

```
clrty> validator register 0x<node-key-hex> 10000 0.01
```

The arguments are the node key, the stake in CLRTY, and the fee. The
stake is taken from your balance and locked against the validator
record. The reward address for the new validator is the address of the
keystore that signs the registration.

The executor rejects the transaction if:

- Your address is already registered.
- The stake is below the network minimum.
- The node key is malformed or null.

### Checking your validator record

```
clrty> validator info
Registered as validator 0x1
  reward address:  clrty1q...
  consensus key:   0x819e...
  node key:        0x819e...
  owner:           clrty1q...
  stake:           0x5f5e100
  registered at:   0x0
  status:          seed
  can be active:   yes
  is offline:      no
  uptime:          10000 bps
  multiplier:      10000 bps
  infractions:     0
```

`status` is one of `seed`, `active`, or `registered (not in active
set)`. A validator that is registered but not active is eligible for
rotation into the active set at the next epoch boundary.

### Updating the reward address

Changes the address that receives block rewards. Does not affect the
consensus key or the validator's participation.

```
clrty> validator update-reward clrty1q... 0.01
```

The executor rejects the transaction if:

- Your address is not a registered validator.
- The new address is the same as the current one.
- The new address is malformed.

Once the transaction confirms, the new address is the validator's
`owner` and reward destination. The old address can no longer update
or unregister it.

### Unregistering

Starts the unbonding countdown.

```
clrty> validator unregister 0.01
```

The validator is removed from the active set immediately, but its
record, key history, and stake persist for the unbonding period.
During that window the validator is still slashable; after it, the
stake is returned to the owner and the record is deleted.

Seed validators cannot be unregistered. The executor also rejects an
unregistration that would drop the active set below the network
minimum.

---

## Advanced topics

### Verified balances

By default, `balance` trusts the node it talks to. To verify a balance
against a state proof:

```
clrty> balance --verify
```

The wallet fetches the current state root, requests an SMT proof for
the account, and verifies the proof locally before reporting the
balance. If you have a second RPC endpoint configured, the wallet
requires both endpoints to agree on the state root before verifying:

```
clrty> connect-peer 192.0.2.11:9633
clrty> balance --verify
  ...
  root confirmed by two independent endpoints
```

Without a peer endpoint, the wallet warns that it is trusting a single
server for the root. The proof is still verified against the root the
server provided, so a server that lies about a balance produces a
failing proof — but a server that lies about the root and produces a
consistent proof against the wrong root would not be caught.

### Working offline

The wallet can start without a node, and it can go offline at any
time. Commands that need a node will fail with `no RPC connection` or
`cannot fetch nonce`; commands that don't (`info`, `close`) keep
working.

This is useful when you want to sign a transaction and submit it
later, or when the node is temporarily down but you want to inspect
your keystore's state.

```
clrty> connect 192.0.2.10:9633
Connected to 192.0.2.10:9633
```

Bring it back when the node is reachable.

### Session state

Everything the wallet knows about your session lives in memory and is
discarded when you exit:

- The open keystore and its unlocked key.
- The RPC endpoint and the connection.
- The last submitted txid (for `status` with no argument).

The only thing that persists is the keystore file on disk. Exiting the
wallet locks the keystore; opening it again requires the password.

---

## Troubleshooting

**`error: no keystore open. Use 'open <path>' first.`**

You're running a command that needs a signing key (`send`, `stake`,
`claim`, `token create`, and so on) with no keystore open. Either
`open <path>` first, or start the wallet with `--keystore <path>`.

**`error: no RPC connection`**

The wallet can't reach the node. Check that the daemon is running and
that the endpoint is correct:

```
clrty> connect 127.0.0.1:9633
```

**`error: cannot fetch nonce: ...`**

The wallet needs the account's current nonce before it can build a
transaction, and the node didn't return one. Most often this is a
connectivity problem — the same as above. If the node is up but the
response is malformed, the message will say so.

**`error: submission failed: ...`**

The node accepted the connection but rejected the transaction. The
message after `submission failed:` is the executor's reason. Common
ones:

- `nonce-too-low` — a pending transaction with a higher nonce is
  blocking. Wait for it to mine, then retry.
- `insufficient funds` — the account doesn't have enough CLRTY for the
  amount plus the fee.
- `already registered` — you're trying to register a validator that's
  already registered. Use `validator info` to see the current state.

**`error: transaction committed but failed.`**

The transaction was included in a block but the executor rejected it.
The receipt is shown, including the fee that was charged. This is
different from `submission failed`: the transaction made it into the
chain, it just didn't do what you asked.

**The wallet starts but the keystore won't unlock.**

The password is wrong, or the keystore file is corrupt. There is no
way to recover a keystore without its password. If you have the BIP-39
mnemonic, you can recreate the keystore with `address --import`.

**`error: no such command '<name>'`**

Typo, or a command that doesn't exist in this build. `help` lists
everything available; `help <name>` gives details on a specific one.

**A number in the output looks like hex (`0x5f5e100`).**

The RPC layer emits every integer as a `"0x"`-prefixed hex string to
avoid JavaScript precision loss above 2^53. The wallet decodes some
of these for display (balances in `balance`, `token supply`, and so
on) but prints others verbatim (`stake`, `max supply`, `registered
at`). Both forms are the same value; if you need the decimal, use a
calculator or `printf '%d' 0x5f5e100`.

---

## Command reference

```
Session:
  info                        Show the open keystore's metadata
  open <path> [--password-file <path>]
                              Open and unlock a keystore
  close                       Lock and close the current keystore
  connect <host:port>         Change the RPC endpoint
  connect-peer <host:port>    Set a second endpoint for proof verification
                              (or `connect-peer none` to clear it)
  help [command]              Show help
  exit, quit                  Exit the wallet

Balances and transfers:
  balance [address] [--verify]
                              Show the native balance of an address
  tokens [address] [--limit N]
                              List all tokens held by an address
  nonce [address]             Show an account's current nonce
  send <to> <amount> <fee> [--token <id>] [--wait] [--dry-run]
                              Send CLRTY, or a non-native token with --token
  status [txid]               Show a transaction receipt

Staking:
  claim <fee> [--wait]        Claim pending rewards
  stake <opt-in|opt-out> <fee> [--wait]
                              Toggle auto-staking

Tokens:
  token list [--limit N] [--offset N]
                              List all tokens
  token show <token-id>       Show a token's metadata
  token supply <token-id>     Show a token's current supply
  token create <name> <symbol> [--decimals N] [--backing 0|1]
               [--max-supply N] [--royalty <bps>]
               [--fingerprint <hex>] <fee> [--wait] [--dry-run]
                              Create a fungible token
  token mint <token-id> <to> <amount> <fee> [--wait] [--dry-run]
                              Mint more of a token you created
  token burn <token-id> <amount> <fee> [--wait] [--dry-run]
                              Burn tokens you hold
  token update <token-id> [--name <text>] [--symbol <text>]
               [--royalty <bps>] <fee> [--wait] [--dry-run]
                              Update a token's metadata

NFTs:
  nft list [--collection <id>] [--limit N] [--offset N]
                              List NFTs you own, or NFTs in a collection
  nft show <nft-id>           Show one NFT's record
  nft mint <collection-id|-> [--uri <uri>] [--hash <hex>] <fee> [--wait]
                              Mint a standalone or collection NFT
  nft wrap <underlying-token-id> <amount> [--collection <id>]
           [--uri <uri>] [--hash <hex>] <fee> [--wait]
                              Mint a wrapped NFT with an underlying balance
  nft transfer <nft-id> <to> <fee> [--wait]
                              Transfer an NFT
  nft burn <nft-id> <fee> [--wait]
                              Burn an NFT
  nft metadata <nft-id> [--uri <uri>] [--hash <hex>] [--freeze]
               <fee> [--wait]
                              Update an NFT's metadata
  nft topup <nft-id> <token-id> <amount> <fee> [--wait]
                              Add underlying to a wrapped NFT
  nft claim <fee> [--wait]    Settle accrued NFT rewards

Collections:
  collection list [--limit N] [--offset N]
                              List all collections
  collection show <collection-id>
                              Show one collection's record
  collection create <name> <symbol> [--uri <uri>] <fee> [--wait]
                              Create a collection with no reward schedule
  collection create <name> <symbol> --reward-token <id>
                    --reward-rate <amount> --escrow <amount>
                    [--uri <uri>] <fee> [--wait]
                              Create a collection with a reward schedule
  collection refill <collection-id> <amount> <fee> [--wait]
                              Add to a collection's reward escrow

Validator:
  validator info              Show your validator record
  validator register <node-key-hex> <stake> <fee> [--wait]
                              Register as a validator
  validator update-reward <new-address> <fee> [--wait]
                              Change your reward address
  validator unregister <fee> [--wait]
                              Start the unbonding countdown
```

---

## Platform notes

The wallet is written for a POSIX environment (Linux, macOS, or WSL).
Its file handling uses POSIX paths and tilde expansion, and the
keystore password prompt uses terminal echo suppression that relies on
POSIX `termios`.

On **Windows**:

- Paths use backslashes, and `~` is not expanded. Pass absolute paths
  or paths relative to the current directory.
- The password prompt may not suppress echo correctly depending on the
  terminal. If your password appears on screen as you type, use
  `--password-file <path>` instead.
- There is no `chmod`, but the wallet does not enforce file permissions
  on the keystore — the keystore's own encryption is the protection.
  Restrict its file permissions with `icacls` if you want an extra
  layer.

For a full cross-platform experience, running the wallet under WSL is
recommended.