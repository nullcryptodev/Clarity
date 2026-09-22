# Consensus Testing Notes

The Consensus module implements BFT consensus. Tests exercise both
single-instance state-machine behavior and multi-instance coordination.

### Types, proposer selection, timer (`TypesTests.cpp`,
`ProposerSelectionTests.cpp`, `RoundTimerTests.cpp`)

Pure functions:
- Step name mapping, including an unknown-step sentinel.
- `Vote::isValid` / `Proposal::isValid` predicates.
- Proposer formula `(height + round) % active_size`, at boundaries
  and with large heights.
- Timer timeout formula `BASE * 2^round`, capped at `MAX`, and
  lifecycle (start/stop/poll).

Two tests exercise the real-time timer path (5+ second sleeps) and
prove the timer fires on wall-clock time. Every other test uses
`forceTimerExpiryForTest` to drive the timer without sleeping.

### Wire serialization (`MessageTests.cpp`)

Round-trip for `Proposal` and `Vote` encode/decode, including nil
votes. Rejects truncated input and oversized block_size fields.
Signing-hash tests verify domain separation (proposal and vote
hashes differ for the same height/round/block) and coverage of every
field.

### Single instance (`BftConsensusTests.cpp`)

The state machine in isolation, driven with hand-delivered votes and
`forceTimerExpiryForTest`. Sections:

- A. Lifecycle (start, propose, stop, height advance)
- B. Proposal handling (accepts valid, rejects wrong height/round/
  signer/signature)
- C. Vote handling (records, ignores duplicates, wrong height/round,
  bad signature)
- D. Quorum (threshold, entering commit, round-crossing commit of
  the quorum block not the latest proposal)
- E. Locking (locks on first prevote, releases on new height)
- F. Vote type routing (precommits during prevote step are dropped,
  prevotes during precommit step are dropped)
- G. Precommit validity (unknown blocks rejected, locked accepted,
  other blocks rejected)
- H. Broadcast type routing (proposal/prevote/precommit each reach
  their own callback)

Section H pins the fix for a bug where precommits were broadcast
through the prevote callback. Any regression that conflates the two
will fail those tests.

### Multi-instance coordination (`MultiValidatorTests.cpp`)

The `ConsensusNetwork` harness owns N `BftConsensus` instances and a
message queue. Broadcast callbacks enqueue; `deliverAll()` drains and
dispatches. `advanceAllTimers()` expires all timers first (every
instance sees the same logical instant), then polls all, then
delivers.

The 11 tests cover:
- Four validators reaching commit.
- All validators agreeing on the committed block.
- Three-of-four quorum with one offline.
- Two-of-four not reaching quorum.
- Two consecutive rounds.
- Determinism: two runs produce the same block hash.
- No fork across all validators.

`now_ms` in `Dependencies` is set to a counter, so identical runs
produce identical blocks. This is what makes the determinism test
possible.

## The boundary this module has

`BftConsensus` produces a `Core::Block` as its output. Any test of
`BftConsensus` that doesn't run that block through
`BlockProcessor::applyBlock` cannot detect a mismatch between what
consensus produces and what the block processor requires. That's the
class of bug this module has historically had.

When adding tests here, prefer ones that run the committed block
through the block processor. When debugging a consensus issue in
production, check first whether the block that was committed satisfies
`Block::isWellFormed()` and `BlockProcessor`'s validation.