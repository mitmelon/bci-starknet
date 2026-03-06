# BCI v1.0 — Behavioral Commitment Identity on Starknet

> *"AI agents that control funds have no secure identity. Any stored credential can be stolen.  
> BCI v1 solves this — identity from BEHAVIOR + MEMORY, anchored on Starknet."*  
> — ZionDefi Research

**Track:** Privacy · **Hackathon:** Re{define} by Starknet / Bitcoin & Privacy Hackathon  
**Tech:** Cairo v2 · Starknet · ZK Fuzzy Commitments · HMAC  

---

## Run in 30 Seconds

```bash
git clone https://github.com/mitmelon/bci-starknet
cd bci-starknet
npm install
cp .env.example .env        # fill in CONTRACT_ADDRESS, ACCOUNT_ADDRESS, PRIVATE_KEY
node src/demo.js
```

**Expected:** 10 demo steps, real Starknet Sepolia transactions submitted, 19/19 unit tests passing.

```bash
# Unit tests only (no .env required):
node src/test_crypto.js

# Deploy contract to Sepolia first:
scarb build
node src/deploy.js

# Then run the live on-chain demo:
node src/demo.js
```

**Setup for live demo:**
1. Deploy `contract/src/lib.cairo` and note the contract address
2. Copy `.env.example` to `.env` and set:
   - `CONTRACT_ADDRESS` — deployed contract address
   - `ACCOUNT_ADDRESS` — your Starknet account (must be set as `relayer` in the constructor)
   - `PRIVATE_KEY` — your account's private key
3. Optionally set `GLOBAL_AGENT_ID` after running `complete_enrollment` (requires 7-day wait) to enable the full authorization demo

---

## The Problem — Agent Identity Trilemma

Every AI agent identity system needs three properties simultaneously:

| Property | Meaning |
|---|---|
| **Unforgeable** | Impostor cannot claim real agent's identity |
| **Portable** | Works on any server that's never seen the agent |
| **Non-custody** | No stored credential in the agent's environment |

Existing approaches satisfy at most two. A stolen API key breaks non-custody. Hardware enclaves break portability. Behavioral biometrics alone break unforgeability. **BCI v1 satisfies all three.**

---

## How It Works

```
ENROLLMENT (7 days):
  Agent makes payment decisions. BCI measures silently:
  latency, token usage, tx amounts, endpoint sequences.

  F_stable = median(observations)            ← 8D feature vector
  B_stable = quantize64(F_stable)            ← 64-bit identity (2^64 space)
  K        = random_bytes(256)               ← ephemeral secret
  C        = K XOR B_stable                  ← fuzzy commitment (hides B)
  MS       = HMAC(K, "MemorySecret:agentId") ← Memory Secret
  seed     = HMAC(MS, "BCI_RESPONSE_SEED")← stored on Starknet
  
  K DESTROYED. MS DESTROYED. Nothing secret persists.

AUTHORIZATION (per payment):
  Phase 1: Server measures behavioral confidence (≥60%) → issues nonce
  Phase 2: P-Process computes HMAC(seed, nonce:agentId) → server verifies
  
  Server learns: "this agent knows MS" — NOT the value of MS.
  That's the zero-knowledge property.
```

---

## Privacy Properties

**What Starknet stores (public — anyone can read):**
- `GlobalAgentID` — pseudonymous, not linked to any real identity
- `enrollment_response_seed` — enables verification, **cannot** recover MS
- `ms_commitment` — proves MS binding, reveals nothing about MS value
- Behavioral tolerances — range parameters only, not raw observations
- Spending limits, lockout state, authorization event log

**What is never stored anywhere (destroyed after enrollment):**
- `K` — secret key, destroyed after creating commitment
- `MS` — Memory Secret, destroyed after provisioning to P-Process
- `B_stable` — raw binary behavioral string (hidden inside `C = K XOR B`)
- Raw behavioral observations

**Zero-knowledge properties:**
- Challenge-response: server learns "agent knows MS" — **not** the MS value
- Fuzzy commitment: `C = K XOR B` → `C` reveals nothing about `B` without `K`
- Confidence check: "behavior matches" — not which patterns or their values

---

## Five v1 Weaknesses Fixed

| # | Weakness | Fix |
|---|---|---|
| 1 | 12-bit binary = 4,096 identities (brute-forceable in microseconds) | 64-bit = 2^64 identities (585 years to brute-force) |
| 2 | BCH oracle attack via timing | `crypto.timingSafeEqual` + 24hr lockout after 3 failures |
| 3 | Memory Secret in LLM context window (extractable via prompt injection) | Dual-Process: P-Process holds seed, LLM never sees it |
| 4 | Model update locks agent out permanently | EMA: `F_new = 0.85×F_old + 0.15×F_current` weekly |
| 5 | **Critical math bug**: verification equation never holds — all legitimate responses fail | HMAC-based construction: both sides compute `HMAC(seed, nonce:agentId)` — equal by construction |

The bug was: `Poseidon(HMAC(MS,nonce,id)) ≠ Poseidon(Poseidon(MS),nonce,id)`. These are different hash computations and never match. 100% of legitimate responses in would fail. We use the HKDF-Expand pattern from TLS 1.3.

---

## Starknet Integration

`BCIAgentIdentity.cairo` (Cairo v2) stores identity commitments and enforces authorization rules on-chain:

```
complete_enrollment(agent_id, commitment_hash, binary_high, binary_low,
                    enrollment_response_seed, ms_commitment, auth_key_hash)
→ Event: EnrollmentCompleted

request_authorization(agent_id, conf_score)
→ Issues nonce if confidence ≥ 60%
→ Event: ChallengeIssued

submit_challenge_response(agent_id, nonce, response)
→ Verifies HMAC on-chain
→ Event: TransactionAuthorized | ChallengeFailed
```

Any server in the world can fetch the public `enrollment_response_seed` from Starknet and verify an agent independently — no shared state, no trusted setup.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Q-Process (LLM Agent — Quarantined)                │
│  • Makes payment decisions                          │
│  • Handles user interaction                         │
│  • Has ZERO access to seed or MS                    │
│  • Sends only hex-64 nonces to P-Process via IPC    │
└─────────────────┬───────────────────────────────────┘
                  │  nonce (validated hex-64 only)
                  ▼  response (opaque hex token)
┌─────────────────────────────────────────────────────┐
│  P-Process (Privileged — NOT an LLM)                │
│  • Holds enrollment_response_seed in memory         │
│  • Computes HMAC(seed, nonce:agent_id)              │
│  • IPC rejects all non-hex input (injection safe)   │
└─────────────────────────────────────────────────────┘
                  │  public verifiers only
                  ▼
┌─────────────────────────────────────────────────────┐
│  Starknet — BCIAgentIdentity.cairo                │
│  • enrollment_response_seed (public)                │
│  • ms_commitment (public)                           │
│  • Authorization rules enforced on-chain            │
│  • Event log: full audit trail                      │
└─────────────────────────────────────────────────────┘
```

---

## Repo Structure

```
contract/
   src/
      lib.cairo                    ← Cairo v2 contract (BCIAgentIdentity)
    Scarb.toml                     ← Cairo package manifest
src/
  demo.js                          ← Full on-chain demo (real Starknet Sepolia)
  test_crypto.js                   ← Unit tests (19/19 passing)
.env.example                       ← Environment variable template
README.md
```

---

## About

**Author:** Adeyeye George  
**Project:** ZionDefi — Self-custodial payment card infrastructure on Starknet  
**Location:** Lagos, Nigeria  

---

*BCI is the identity primitive that the AI payments ecosystem has been missing.  
The agent from lagos server is still the same agent in Canada — provably, privately, on Starknet.*