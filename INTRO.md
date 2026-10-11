# What is Clarity?

A fast, cheap blockchain where the people who keep the network running are
accountable to the people who use it.

Clarity is a new blockchain with its own currency ($CLRTY). Validators — the
computers that produce blocks — rotate regularly, so no single operator can
control the chain. When a validator tries to cheat, the network has
cryptographic proof, and the cheater loses part of their stake.

**This document is for two kinds of readers:**

- [**If you want to use Clarity**](#if-you-want-to-use-clarity) — hold or spend
  CLRTY, create a token, earn staking rewards.
- [**If you want to run a validator**](#if-you-want-to-run-a-validator) — help
  keep the network running and earn CLRTY for it.

A plain-English introduction. If you want the technical version, see the
[main README](README.md).

## The short version

- **Fast.** Blocks are designed to come every **1 second**. In practice, the
  network targets continuous production with no waiting around.
- **Cheap.** Transaction fees are a fraction of a CLRTY and are set by the
  sender. Higher fees get priority when the network is busy.
- **Final.** Once a block commits, it's committed. There is no waiting for
  confirmations, no longest-chain rule, no risk of a reorg.
- **Honest.** Most of the validators have to agree before anything happens.
  A validator that tries to cheat loses money.
- **Pre-launch.** The network is running on a private test network for
  development. It is not open to the public yet.

## If you want to use Clarity

### What you can do

- **Send CLRTY** from one address to another. Fast and cheap, like an email
  that carries money.
- **Create your own token.** Name it, give it a symbol and decimals, set a
  maximum supply. You can mint more up to the cap (only you), and burn it
  from circulation.
- **Trade tokens** through a built-in marketplace (an automated market
  maker). Provide liquidity to earn fees from other people's trades, or
  swap one token for another.
- **Stake CLRTY** to earn rewards. Any balance over 100 CLRTY is staked
  automatically. You can opt out at any time.
- **Claim staking rewards.** Rewards accrue every epoch (~1 minute) and can
  be moved into your spendable balance whenever you want.

### How much you can earn

Staking rewards pay a **base of 5% per year**, plus up to **5% more** when
the network is busy and up to **3% more** when the reward pool is full.

That's a **maximum of about 13% per year** under ideal conditions. The
actual rate depends on how active the chain is.

If you hold at least 1,000 CLRTY staked, your rewards are weighted 3%
higher than a smaller staker's.

### What it costs

Every transaction pays a fee in CLRTY. The sender chooses the amount;
higher fees get priority when blocks are full. In practice, a transfer
costs a small fraction of a CLRTY.

Staking itself is free. There is no lock-up, no withdrawal delay. Your
CLRTY stays spendable even while it's earning rewards.

### What's not ready yet

- The network isn't live. Clarity is being tested on a private network.
- There is no exchange integration yet. When the network launches, you'll
  get CLRTY by running a validator, by staking, or by receiving it from
  someone who already has some.
- A graphical wallet is planned, but today the wallet is a command-line
  tool. If you've used a hardware wallet or a desktop wallet before, the
  interface will be different.

## If you want to run a validator

A validator is a computer that helps produce the chain. Validators take
turns: at every height, one of them proposes a block, and the rest vote on
whether it's valid. When enough vote yes, the block commits.

Validators earn CLRTY for this. They're the backbone of the network.

### What you need

- **At least 1,000 CLRTY staked.** This is the minimum to register.
- **A small server.** A modest cloud VPS is sufficient. Detailed
  requirements will be published before mainnet launch.
- **Reliable uptime.** See below — going offline costs you rewards but
  does not cost you your stake.

### What you earn

Every block pays 10 CLRTY. Of that:

- **60% goes to the validator set.** Of the validators' share, the one who
  produced the block earns an extra bonus, and the rest is split equally
  among all active validators.
- **40% goes to stakers** (the people who hold CLRTY and are earning
  staking rewards).

A validator earns from every block it participates in, not only the ones
it produces. With the current active-set size, that's a steady stream of
rewards for being online and honest.

On top of this, a validator's own stake earns the same staking rewards
described above.

### What happens if you go offline

**You lose the rewards you would have earned. You do not lose your
stake.** Offline validators are removed from the active set after 20
consecutive missed blocks and can rejoin once they're back online.

This is deliberate. A network blip, a bad ISP, a reboot — none of these
should cost you money. Only cheating does.

### What happens if you cheat

A validator "cheats" by signing two conflicting blocks at the same height
— for example, voting for two different versions of the same block. This
is called equivocation, and it's the only thing that gets a validator
slashed.

When someone produces a cryptographic proof that a validator equivocated:

- **5% of that validator's stake is slashed.**
- **The validator's future rewards are permanently reduced by 20%**, and
  this stacks. A validator who equivocates repeatedly loses more.
- Slashed CLRTY goes into the reward pool that pays stakers.

There is no vote, no appeal, no discretion. The proof is a mathematical
fact, and any node can verify it. The network enforces the penalty
automatically.

Seeds — the two bootstrap validators run by the project itself — are
exempt from slashing. This is a governance safeguard, not a privilege.

### How you exit

If you decide to stop being a validator, you can unregister at any time.
Your stake is returned after a short unbonding period of 120 blocks
(~2 minutes). During that window, the network still treats your validator
as live — this is so any evidence of cheating that surfaces shortly after
you leave can still be applied.

Seeds cannot unregister.

## How the network stays honest

Most validators have to agree before a block commits. Out of every 100
validators, up to 33 could be offline or malicious and the network would
still work correctly. In a smaller set, the ratio is tighter but the
principle is the same.

When a validator cheats, its misbehavior is a mathematical fact anyone can
verify. The network applies the penalty automatically. There is no
committee deciding who to punish, no vote, no appeal.

Validators also rotate. The set of active validators changes every epoch
(~1 minute). This makes it harder for a group to collude, and it means
that no small group permanently controls the chain.

The result is a network where being honest is the most profitable strategy,
and cheating has a predictable cost.

## What's not ready yet

Clarity is in **pre-launch development**. The daemon builds, the test
suite passes, and the network has been exercised on a private two-validator
test environment. But:

- **The network isn't open to the public yet.** No mainnet launch date has
  been announced.
- **The order book (limit orders) is not yet implemented.** The chain
  supports creating and cancelling orders in its state model, but the
  matching engine — the part that actually fills them — is still in
  development. Use the AMM for trading.
- **A graphical wallet is planned**, but today's wallet is a command-line
  tool.
- **There is no mobile wallet, no browser extension, no third-party
  exchange integration.**

When this changes, the README and this document will be updated.

## Where to go next

- **[README](README.md)** — the technical reference. Everything from
  consensus protocol to state proofs to wire formats.
- **[Economics of Clarity](docs/ECONOMICS.md)** — a deeper look at the
  reward system and the pot mechanism.
- **[Setup Clarity REGTEST](docs/SETUP-REGTEST.md)** — how to spin up a
  local test network and try things yourself.
- **[Clarity Metrics Reference](docs/METRICS.md)** — what the Prometheus
  endpoint exposes, for operators.
- **[Discord](https://discord.gg/gGjnyvxwFp)** — questions, feedback,
  and development discussion.
