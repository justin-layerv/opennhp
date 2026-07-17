# 2026-07-14 · Issue #3226 · Bind connector knocks to FRP login cycles

- **Owner:** qURL Connector rollout coordinator
- **Source:** [NHP #3226](https://github.com/layervai/nhp/issues/3226), [qURL Connector #421](https://github.com/layervai/qurl-connector/issues/421), [qURL Connector #424](https://github.com/layervai/qurl-connector/issues/424), [qURL Go #66](https://github.com/layervai/qurl-go/issues/66), [qRTS #221](https://github.com/layervai/qurl-reverse-tunnel-server/pull/221)

The registered-agent UDP boundary becomes fail-closed for a missing or noncanonical cycle RunID. Keep this PR draft until the SDK, FRP seed API, Connector lifecycle/recovery path, and qRTS consumer can move through sandbox as one coordinated contract.

- [ ] Pre-rollout: prove the NHP #3224 validator image and zero-tolerance alarm in production before promoting this stored-RunID producer.
- [ ] Cross-repo: release qurl-go #66 with mandatory pre-I/O `NativeKnockOptions.RunID`, release the supported FRP InitialRunID API tracked by qURL Connector #424, and make qURL Connector #421's once-per-cycle seed plus bounded fresh-cycle recovery ready before merging this PR.
- [ ] Rollout: coordinate the sandbox NHP deployment with qRTS #221 and the qURL Connector cutover; do not leave an old Connector sending registered-agent knocks without `runId` against this gate.
- [ ] Post-rollout: retain sandbox proof that one RunID is byte-identical through authenticated KNK, local/shared ACK metadata, validator request/response, first and reconnect FRP Login, and SessionStore; also prove omission/mismatch denial and new-cycle rotation.
- [ ] Rollback: disable Connector traffic first, then restore the preceding qRTS and NHP images together; do not re-enable traffic with only one side of the RunID contract rolled back.
