# commonware-consensus

[![Crates.io](https://img.shields.io/crates/v/commonware-consensus.svg)](https://crates.io/crates/commonware-consensus)

Order opaque messages in a Byzantine environment.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Experimental Minimmit

The CavalRe fork exposes `commonware_consensus::minimmit` at ALPHA stability.
It ports the experimental `cl/minimmit` implementation from
[`bd834b53f8447ce378605c7c3e04979483627ae0`](https://github.com/commonwarexyz/monorepo/commit/bd834b53f8447ce378605c7c3e04979483627ae0)
to the 2026.9 APIs, under the repository's MIT OR Apache-2.0 licenses.

Minimmit uses a `5f+1` committee, with `2f+1` votes for progress and `n-f` votes
for finalization. `QuorumScheme` keeps these certificate thresholds explicit;
a progress certificate must not pass finalization verification. The integration
uses the current certificate verifier, supervisor, registered metrics, consuming
journal and resolver delivery APIs. The original deterministic tests, twins
partition strategies and codec fixtures are retained.

From the repository root:

```sh
just test -p commonware-consensus minimmit::
just test -p commonware-consensus --features arbitrary --profile conformance minimmit::
just clippy -p commonware-consensus
just check-stability BETA -p commonware-consensus
```

This is experimental consensus code. Passing regression tests is not a proof
of protocol safety or a production readiness assessment.
