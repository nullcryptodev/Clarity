<img src='https://github.com/nullcryptodev/docs/blob/main/clarity/clarity-wide.png?raw=true'>

# NFTs on Clarity

## Table of Contents

- [What is an NFT?](#what-is-an-nft)
- [What makes Clarity's NFTs different](#what-makes-claritys-nfts-different)
- [The two kinds of NFTs](#the-two-kinds-of-nfts)
  - [Standalone NFTs](#standalone-nfts)
  - [Wrapped NFTs](#wrapped-nfts)
- [Collections](#collections)
- [Reward schedules](#reward-schedules)
- [Ownership, transfers, and burning](#ownership-transfers-and-burning)
- [Metadata and freezing](#metadata-and-freezing)
- [Real scenarios](#real-scenarios)
  - [A digital collectible](#a-digital-collectible)
  - [A drop of 10,000](#a-drop-of-10000)
  - [A wrapper for a DeFi position](#a-wrapper-for-a-defi-position)
  - [A reward-bearing membership](#a-reward-bearing-membership)
  - [Nested NFTs and collection groups](#nested-nfts-and-collection-groups)
- [What NFTs on Clarity don't have](#what-nfts-on-clarity-dont-have)
- [Common questions](#common-questions)

## What is an NFT?

An NFT is a **non-fungible token** — a token that is unique. One NFT is not
interchangeable with another the way one dollar bill is interchangeable with
another dollar bill. Each NFT has its own identity, its own owner, and
usually its own meaning.

On most chains, an NFT is a smart contract that stores an owner's address, a
link to some content, and some code that decides what the NFT can do. On
Clarity, it's simpler than that: an NFT is a **record in the chain's state**,
the same way an account or a token balance is a record. No smart contract, no
code to run, no fees to pay for the code to run.

If you're used to NFTs on other chains, the short version is: everything
you'd expect works, but without the contract layer that usually sits between
you and the chain.

## What makes Clarity's NFTs different

Four things, and they add up.

**1. Every NFT is also a token.**

When you create an NFT on Clarity, the chain also creates a "shadow token" —
a normal token whose total supply is exactly 1. This token is what the rest
of the chain sees when it looks at your NFT. The DEX can trade it, the
AMM can quote it, the reward system can pay it. Nothing on the chain needs to
know that the token is actually an NFT underneath.

What this means for you: an NFT on Clarity is instantly usable everywhere a
regular token is. You don't need a special marketplace or a special
integration. If a feature works with a token, it works with your NFT.

**2. Nothing is off-chain except the metadata.**

There is no contract that lives somewhere else. The NFT's existence, its
owner, its collection, its reward schedule, and its wrap status are all part
of the chain's state. A light client with a single state root can prove your
NFT exists and who owns it, without asking anyone.

The one thing that lives off-chain is the *content* — the image, the video,
the document. That's normal for NFTs everywhere. The chain stores a pointer
(a URL) and usually a hash of the content, so anyone who fetches the content
can verify it matches what the chain promised.

**3. Wrapped NFTs are actual custody.**

Some NFTs on Clarity can "wrap" another token — hold it inside themselves.
When you wrap 100 units of a token, the 100 units are really held by the NFT,
in a real account that only the NFT's owner controls. If you sell the NFT,
you sell the 100 units with it. If you burn the NFT, the 100 units come back
to you.

There's no trust involved. The custody isn't a promise by a contract to hold
the token; it's a balance sitting at an address derived from the NFT's id.

**4. Reward schedules pay NFT holders directly.**

A collection of NFTs can carry a reward schedule — a rate at which each
holder earns some other token, paid out of an escrow that the creator funded
up front. Once the schedule is set and the escrow is funded, the chain pays
it. No claim contract, no merkle tree, no snapshot. The escrow decrements
every epoch, and holders collect from it as they wish.

## The two kinds of NFTs

On Clarity, every NFT is either **standalone** or **wrapped**. They share
almost everything; the difference is whether the NFT is backed by another
token.

### Standalone NFTs

A standalone NFT is the simple case. It exists, it has an owner, it has some
metadata. Nothing backs it. It's just a thing.

**Good for:** digital collectibles, art, membership passes, name registrations,
claim tickets, badges — anything whose value comes from what it represents
rather than from what it holds.

**Example:** Alice mints an NFT representing a piece of digital art. The NFT
records a content hash (which commits to the image's contents) and a URL (where
the image can be found). Alice owns it. When she sells it, the buyer gets the
same pointer and the same ownership.

### Wrapped NFTs

A wrapped NFT holds an amount of another token in custody. Whoever owns the
NFT owns the tokens it holds.

**Good for:** tokenizing a position, packaging a bundle of tokens into a
tradeable object, selling a "share" of a large holding, representing a
staking position, wrapping one NFT inside another.

**Example:** Alice has 5,000 units of a fungible token she doesn't want to
sell piecemeal. She wraps all 5,000 into an NFT. The NFT now holds the
5,000 units. Alice can sell the NFT as a single object. The buyer, when they
receive the NFT, controls the 5,000 units. When the buyer wants the units
back, they burn the NFT and the units return to them.

**Example:** Bob has an LP position in the AMM. He wraps the position's
tokens into an NFT, creating a tradeable object that represents "my share of
this pool." He sells the NFT on the DEX. The buyer now owns the LP position.

Wrapped NFTs can be topped up. If you own a wrapped NFT, anyone can send
more of the underlying token to it, and the NFT's value goes up. This is how
a "tip jar" or a "growing collectible" would work.

## Collections

A collection groups related NFTs together. It gives them a shared name, a
shared symbol, and optionally a shared base URL for their metadata.

A collection is optional. A standalone NFT with no collection is fine — it's
the "throwaway" case, useful when you just want one NFT and don't care about
grouping it with anything.

**Collections do three jobs:**

1. **Grouping.** A "Punks" collection makes it easy for a marketplace or a
   wallet to display your 500 Punks as one group rather than 500 unrelated
   items.

2. **Metadata templates.** If a collection has a base URL like
   `https://example.com/punks/`, an NFT in that collection with an empty
   metadata URL is understood to inherit it, and the chain knows to append the
   NFT's id. So NFT #42 in the Punks collection would be looked up at
   `https://example.com/punks/42`.

3. **Reward schedules.** If the collection carries a reward schedule, every
   NFT in it earns the same rate from the same escrow. See the next section.

A collection is created with one transaction. NFTs are minted into it with
their own transactions, one per NFT. A collection tracks how many NFTs it
currently contains; burning an NFT decrements that count.

## Reward schedules

A collection can carry a reward schedule. This is how you set up "hold this
NFT, earn this much of this other token, every so often."

**How it works, in plain terms:**

The creator funds an escrow up front. The chain holds those tokens on behalf
of the collection. Every 60 blocks (one epoch), the chain moves a small
amount from the escrow to a "pending rewards" bucket, sized by how many NFTs
are currently in the collection and the rate the creator set. Holders collect
from their bucket whenever they want.

If the escrow runs out, the schedule pauses. The creator can refill it to
resume.

**Why the escrow matters:** The reward schedule only makes promises the escrow
can keep. A creator can't advertise a reward rate and then not pay it, because
the tokens are already held by the chain. If the escrow is empty, the schedule
simply stops until it's refilled. There's no "the creator said they'd pay
but didn't" failure mode.

**What you need to know as a holder:** You earn rewards every epoch that
you hold an NFT in the collection. To see them in your balance, you claim
them — the same way you claim staking rewards. Until you claim, your rewards
sit in the pending bucket, still yours, just not yet in your spendable
balance.

**What you need to know as a creator:** You set the rate and fund the escrow
at collection creation. You can refill it later. The rate is per NFT per
epoch, so a collection of 10,000 NFTs at a rate of 1 token per NFT per epoch
obligates the escrow to 10,000 tokens per epoch. If your escrow holds
1,000,000 tokens, the schedule runs for 100 epochs.

**Why it's per-collection, not per-NFT:** A 10,000-NFT collection with the
same rate for every NFT is much cheaper to track as one schedule than as
10,000 separate schedules. Every NFT in a collection earns the same rate.
If you want different rates for different NFTs, put them in different
collections.

## Ownership, transfers, and burning

**Owning an NFT** means your address is recorded as its owner, and you hold
the shadow token that represents it. Both are updated together whenever the
NFT moves. A wallet that only understands tokens still sees the change when
the shadow token moves from one address to another.

**Transferring an NFT** moves ownership to someone else. If the NFT is
wrapped, the tokens it holds stay inside the NFT — they don't move with the
transfer. What moves is the *right to control* those tokens. The new owner
can burn the NFT to release them, or sell the NFT again to pass the control
onward.

**Burning an NFT** destroys it. If it was standalone, that's the end of it.
If it was wrapped, the tokens it held are released to the owner who burned
it. Burning an NFT in a collection decrements the collection's count.

**Rewards accrue until the moment of transfer or burn.** If you're holding an
NFT that's earned 30 units of reward and you sell it, you keep the 30 units.
The buyer starts earning from the moment they receive it. Neither side loses
what they earned.

## Metadata and freezing

An NFT's metadata is a content hash and/or a URL. Both are optional. Both can
be set at mint time and updated later by the owner.

- **The content hash** is a cryptographic commitment to the content. Anyone
  who fetches the content and hashes it can verify that what they got is what
  the chain promised.
- **The URL** is a hint for where to find the content. The chain doesn't
  verify that the URL works; it just stores it.

A holder can **freeze** their NFT's metadata, which makes it permanent. After
freezing, no one — not the holder, not the creator, not anyone — can change
the metadata again. This is useful for NFTs whose provenance matters: once
frozen, anyone can verify that the metadata is exactly what it was at the
moment of freezing.

A frozen NFT can still be transferred and still be burned. Freezing locks the
metadata, not the NFT.

## Real scenarios

### A digital collectible

Alice creates a piece of digital art. She uploads it somewhere (IPFS, her own
server, wherever) and computes its hash. She creates a standalone NFT, sets
the metadata hash and URL to point at the art, and mints it. She owns the NFT.

She lists the NFT on the DEX. Bob sees it, buys it with CLRTY. The NFT moves
to Bob. Bob's wallet now shows a token with a supply of 1 — the shadow token —
that represents ownership of the art.

If Bob tries to edit the metadata, he can — he owns the NFT. If he doesn't
want anyone (including future owners) to be able to edit it, he freezes it.
After freezing, the metadata is what it was, forever.

### A drop of 10,000

A creator wants to release 10,000 generative artworks. She creates a collection
called "Generative" with a base URL for the metadata. She mints 10,000 NFTs
into it. Each NFT has its own metadata hash and its own URL suffix that the
collection's base URL combines with.

If she wants, she can attach a reward schedule. Say, 1 unit of a companion
token per NFT per epoch, escrowed with 1,000,000 units. That's 100 epochs
worth of rewards, distributed evenly across the 10,000 holders.

Every holder earns 1 unit per epoch they hold their NFT. To see it in their
balance, they claim. The chain moves their share from the escrow's pending
bucket to their pending rewards, and from there to their balance when they
claim rewards.

### A wrapper for a DeFi position

Bob has an LP position in the CLRTY/TOKEN pool. He wants to sell it, but the
position isn't tradeable as-is — it's a record on the chain that only he can
operate.

Bob wraps the position. The wrap transaction creates an NFT that holds the
LP tokens. The NFT is a regular token now, so Bob can list it on the DEX. He
sets a price in CLRTY. Carol buys it.

Carol now owns an NFT that holds the LP position. She can burn the NFT to
release the tokens back to herself, at which point she holds the LP tokens
directly and can operate the position.

If the position earns fees while Carol owns the NFT, the fees accrue inside
the NFT's custody. When Carol burns the NFT, she gets the tokens and the fees
that accumulated.

### A reward-bearing membership

A project wants to reward its supporters. It creates a collection called
"Founders" with 100 NFTs, each representing a membership. It funds a reward
escrow with a large quantity of the project's token. Every epoch, each
Founders NFT earns its holder some of that token.

Supporters buy Founders NFTs on the DEX. They hold them, earn rewards every
epoch, and claim whenever they want. The tokens come from the escrow; the
project doesn't have to do anything to pay them. The chain pays them.

If the escrow runs low, the project refills it. If the project runs out of
tokens entirely, the schedule pauses until they refund it. Holders still own
their NFTs and still hold whatever they've already earned.

### Nested NFTs and collection groups

Because every NFT is also a token, and because wrapped NFTs hold tokens, you can put one NFT inside another. This gives projects two useful patterns.

**Pattern 1: one project, many collections.**

A project often has more than one kind of thing to release. A game might have characters, weapons, and land. A fashion brand might have seasons, and each season its own collection. A DAO might mint membership NFTs in different tiers — bronze, silver, gold.

On many chains, each of those would be a separate contract with its own marketplace listing, its own discoverability, its own front-end integration. On Clarity, they can all live under one umbrella: a single "parent" NFT whose shadow token is held by each of the child collections.

Concretely: the project mints a parent NFT that represents the whole umbrella. Each child collection is a normal collection — bronze, silver, gold — created as usual. When the project wants to bring a child collection under the umbrella, it wraps the child collection's shadow token into the parent. Now the parent holds a reference to the child, and a client that reads the parent can discover the child by following the wrap.

The umbrella NFT is a table of contents. It doesn't hold the individual NFTs — those still belong to their holders — it holds a reference to each *collection*, which is what a marketplace or a game needs to display "here are all the project's collections."

**Example:** A game mints three collections — Characters, Weapons, Land. It wraps each collection's shadow token into a single Game NFT. A wallet that reads the Game NFT learns that the project has three collections, and can display them together. When the game adds a fourth collection, it wraps that one into the Game NFT too. The wallet sees the new collection the next time it reads, without the game having to update anything in the wallet.

**Pattern 2: an NFT that holds another NFT.**

Say Alice owns a rare NFT (NFT A). She wants to sell "the right to receive NFT A at some future date" as a separate tradeable object. She wraps NFT A's shadow token into a new NFT (NFT B). NFT B now holds NFT A.

Alice sells NFT B to Bob. Bob owns NFT B, which holds NFT A. When Bob wants NFT A back, he burns NFT B and NFT A's shadow token is released to him. Ownership of NFT A follows.

**Pattern 3: nested wrappers, arbitrarily deep.**

Because a wrapped NFT's underlying is just a token, and a shadow token is just a token, you can wrap a wrapped NFT inside yet another NFT. This gives an arbitrarily deep hierarchy — a parent NFT holding a child NFT holding a grandchild NFT, and so on.

The chain doesn't distinguish "depth" in the model. Every level is a wrapped NFT whose underlying token is another NFT's shadow token. A client that wants to display a hierarchy walks the wrap chain one level at a time.

**All three patterns are legal, supported, and require nothing special.** The chain just sees NFTs holding tokens, and tokens being held by NFTs. Everything else is what a client chooses to do with that.

## What NFTs on Clarity don't have

A few things you might expect from other chains that aren't part of v1.

**No royalties enforced at the protocol level.** A token can declare a royalty,
and a marketplace can choose to honor it, but the chain doesn't force it. This
is the same as every other chain — no chain enforces royalties without a
trusted party, no matter what their marketing says.

**No batch minting.** Minting 10,000 NFTs is 10,000 transactions. There's no
"mint 10,000 in one go" transaction in v1. This is a convenience gap, not a
limitation; a service provider that wants to do a large drop just submits
many transactions, one per NFT.

**No collection deletion.** A collection can be created, but it can't be
deleted while NFTs reference it. In v1 there's no deletion at all. If you
need to stop using a collection, you stop minting into it; the record stays.

**No built-in marketplace.** The DEX is the place where NFTs are traded, the
same as any other token. There's no separate NFT marketplace with auctions,
bids, and so on. Everything a marketplace needs is available (the NFTs, their
metadata, their ownership, their reward schedules), but the marketplace layer
itself is not part of the chain.

**No cross-chain bridging.** NFTs on Clarity are NFTs on Clarity. There is
no bridge to another chain's NFTs. If a project wants to represent an NFT
from another chain, it would mint a corresponding NFT on Clarity that
references the external one — but that's a project's choice, not a chain
feature.

**Rewards are claimed, not pushed.** Your NFT's reward does not appear in
your balance automatically. You claim it. This is the same as staking
rewards, and it's the right design — pushing rewards to every holder every
epoch would be prohibitively expensive, while claiming lets each holder
choose when to act.

## Common questions

**Do I need to create a token before I can create an NFT?**

No. When you mint an NFT, the chain creates the shadow token for you
automatically. From your point of view, you're just minting an NFT.

**Can I have an NFT with no metadata?**

Yes. A bare NFT — no hash, no URL — is valid. It's just a thing with an
owner and an id. Useful for a claim ticket, an internal marker, or anything
else where the value is in the ownership itself.

**Can someone else edit my NFT's metadata?**

No. Only the owner can edit an NFT's metadata. If the owner freezes the
metadata, no one can edit it, including the owner.

**Can I transfer an NFT to a contract or an application?**

Any address can own an NFT. If the address is controlled by an application,
the application can operate the NFT the same way a person can. There's no
distinction between "person" and "application" addresses in the state layer.

**What happens if I lose the private key to my NFT?**

You lose the NFT. There's no recovery, no admin override, no support ticket.
This is the same as any other crypto asset. Keep your keys safe.

**What happens to my NFT's rewards if I sell it?**

The rewards you've already accrued are yours. When you sell the NFT, the
chain settles your accrued rewards to your pending bucket first, then moves
the NFT to the buyer. The buyer starts earning from the moment they receive
it.

**Can I create an NFT that nobody can ever transfer?**

Not in v1. All NFTs are transferable. A future version could add a
"non-transferable" flag, but it's not there today.

**Can the creator take my NFT back?**

No. Once an NFT is minted and transferred to you, the creator has no special
authority over it. They can't recall it, edit its metadata, or change its
reward schedule. The only thing the creator can do that you can't is refill
a collection's reward escrow.

**Does the NFT's image live on the chain?**

No. The chain stores a hash and a URL, not the image itself. This is the same
as every chain — putting images on-chain is prohibitively expensive and
almost never what you want. The hash is what makes the NFT's metadata
verifiable, and the URL is where to find it.

**What if the URL stops working?**

You still own the NFT and the chain still knows what it promised (the hash).
But you can't fetch the content anymore unless someone rehosts it. This is
why content hashes matter: if anyone has a copy of the content and it matches
the hash, the content can be rehosted and the NFT's value is intact. The
chain doesn't care where the content lives; it only cares that the hash
matches.

**Can I create an NFT that holds another NFT?**

Yes. Wrap the inner NFT's shadow token. This is a first-class operation, not
a hack. See the "Nested NFTs" scenario above.

**Are NFTs on Clarity compatible with wallets on other chains?**

No. An NFT on Clarity is a record on Clarity. A wallet that wants to display
it has to understand Clarity's RPC methods, the same way it would have to
understand any other chain's RPC methods. The wallet layer is not bridged.

**How do I know an NFT's reward schedule is actually funded?**

Read the collection's record. It has an `escrow_remaining` field. If it's
positive, the schedule is funded and active. If it's zero, the schedule is
paused. There's no separate "trust me" step — the escrow balance is the
truth, and it's part of the chain's state, so anyone can verify it.
