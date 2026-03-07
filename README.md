<div align="center">

# 🧠 BCI — Behavioral Commitment Identity

### *Zero-Knowledge AI Agent Identity on Starknet*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cairo](https://img.shields.io/badge/Cairo-v2-orange.svg)](https://book.cairo-lang.org/)
[![Starknet](https://img.shields.io/badge/Starknet-Sepolia-blueviolet.svg)](https://starknet.io/)
[![Research](https://img.shields.io/badge/Research-Zenodo%2018888283-blue.svg)](https://zenodo.org/records/18888283)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/mitmelon/bci-starknet)
[![Status](https://img.shields.io/badge/status-experimental-red.svg)](#️-disclaimer)

<br/>

> *"AI agents that control funds have no secure identity.*
> *Any stored credential can be stolen.*
> *BCI solves this — identity from **behavior** + **memory**, anchored on Starknet."*
>
> — Adeyeye George, ZionDefi Research

<br/>

**📄 Research Paper:** [Zenodo Record 18888283](https://zenodo.org/records/18888283)
**🏆 Track:** Privacy · Re{define} by Starknet / Bitcoin & Privacy Hackathon
**🔬 Built for:** ZionDefi Smart Cards — AI agents owning and controlling payment cards on Starknet

</div>

---

## 📖 Table of Contents

- [The Origin Story](#-the-origin-story)
- [The Problem — Agent Identity Trilemma](#-the-problem--agent-identity-trilemma)
- [How It Works](#️-how-it-works)
- [Quick Start](#-quick-start)
- [Deploy with sncast](#️-deploy-with-sncast)
- [Environment Setup](#-environment-setup)
- [Architecture](#️-architecture--dual-process-model)
- [Privacy Properties](#-privacy-properties)
- [Security Fixes in v1.0](#️-security-fixes-in-v10)
- [Repo Structure](#-repo-structure)
- [Milestones & Roadmap](#️-milestones--roadmap)
- [V2 Preview](#-v2-preview)
- [Contributing](#-contributing)
- [Citation](#-citation--research-use)
- [Sponsorship](#-sponsorship)
- [Disclaimer](#️-disclaimer)
- [Author](#-author)

---

## 🏦 The Origin Story

**BCI was born out of ZionDefi** — a self-custodial AI-powered payment card infrastructure being built on Starknet.

The vision: **AI agents should be able to own and transact with smart payment cards**, just like a human cardholder would. An agent could be authorized to make purchases, manage subscriptions, or control spending limits on behalf of a user — all on-chain, all verifiable.

But one problem immediately became clear:

> *If an AI agent controls a card, how does the system know it's the **real** agent and not an impostor?*

Traditional approaches rely on API keys, private keys, or session tokens — all of which live in the agent's environment and can be stolen, leaked via prompt injection, or extracted from logs.

**BCI v1 is the identity primitive we built to solve this.** It lets an agent prove it is itself — not by presenting a credential, but by demonstrating its behavioral fingerprint and proving cryptographic knowledge of a secret it derived during enrollment, anchored immutably on Starknet.

The ZionDefi smart card checks this identity on every transaction. No credential. No theft surface. Just behavior + memory.

---

## 🔺 The Problem — Agent Identity Trilemma

Every AI agent identity system needs all three properties simultaneously:

| Property | Meaning | Why it's hard |
|---|---|---|
| **Unforgeable** | An impostor cannot claim the real agent's identity | Behavioral data is public-observable |
| **Portable** | Works on any server that has never seen the agent | No shared state or prior trust |
| **Non-custody** | No stored credential in the agent's environment | Anything stored can be stolen |

Existing approaches fail:

- 🔑 **API key** → breaks Non-custody (stolen from env)
- 🔒 **Hardware enclave** → breaks Portability (server-specific)
- 📊 **Behavioral biometrics alone** → breaks Unforgeability (observable patterns can be replicated)

**BCI v1 satisfies all three simultaneously.**

---

## ⚙️ How It Works

```
╔══════════════════════════════════════════════════════════════╗
║  ENROLLMENT  (7-day observation window)                      ║
╠══════════════════════════════════════════════════════════════╣
║  Agent makes payment decisions. BCI watches silently:        ║
║  latency · token usage · tx amounts · endpoint sequences     ║
║                                                              ║
║  F_stable = median(observations)   ← 8D feature vector       ║
║  B_stable = quantize64(F_stable)   ← 64-bit identity         ║
║  K        = random_bytes(256)      ← ephemeral secret        ║
║  C        = K XOR B_stable         ← fuzzy commitment        ║
║  MS       = HMAC(K, "MemorySecret:agentId")  ← Memory Secret ║
║  seed     = HMAC(MS, "BCI_RESPONSE_SEED") → stored on-chain  ║
║                                                              ║
║  K DESTROYED. MS DESTROYED. Nothing secret ever persists.    ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║  AUTHORIZATION  (per payment / per transaction)              ║
╠══════════════════════════════════════════════════════════════╣
║  Phase 1: Server measures behavioral confidence  (≥ 60%)     ║
║           → request_authorization(agent_id, score, ...)      ║
║           → Contract issues nonce (60-second expiry)         ║
║                                                              ║
║  Phase 2: P-Process computes poseidon(nonce, seed)           ║
║           → submit_challenge_response(agent_id, nonce, ...)  ║
║           → Contract verifies on-chain — APPROVED / BLOCKED  ║
║                                                              ║
║  Server learns: "this agent knows MS" — NOT the MS value.    ║
║  That's the zero-knowledge property.                         ║
╚══════════════════════════════════════════════════════════════╝
```

The identity space is **2⁶⁴ = 18.4 quintillion** unique identities. Brute-force at 1 billion attempts/second = **585 years**.

---

## 🚀 Quick Start

```bash
git clone https://github.com/mitmelon/bci-starknet
cd bci-starknet
npm install

# Unit tests — no .env required
node src/test_crypto.js

# Full on-chain demo — requires .env
cp .env.example .env        # fill in values (see Environment Setup below)
node src/demo.js
```

> 💡 **Skip deployment — use our live Sepolia contract:**
> The contract is already deployed on Starknet Sepolia at:
> ```
> 0x03d6466ad06b5eede41b1e6e257388ebe8f4bd9cb3be1d081b999fa35c0eb218
> ```
> Just set `CONTRACT_ADDRESS` to this value in your `.env` and you're good to go.
> [View on Starkscan ↗](https://sepolia.voyager.online/contract/0x03d6466ad06b5eede41b1e6e257388ebe8f4bd9cb3be1d081b999fa35c0eb218)

**Expected output:**
- ✅ 10 demo steps executed
- ✅ Real Starknet Sepolia transactions submitted
- ✅ `EnrollmentStarted`, `ChallengeIssued`, `TransactionAuthorized` events emitted on-chain

---

## 🛠️ Deploy with sncast

> **Optional** — A live contract is already deployed on Sepolia at `0x03d6466ad06b5eede41b1e6e257388ebe8f4bd9cb3be1d081b999fa35c0eb218`. You only need to follow these steps if you want to deploy your own instance (e.g. Mainnet, private network, or a fresh Sepolia deployment with yourself as both owner and relayer).

Install the Starknet Foundry toolchain first:

```bash
curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh
snfoundryup
```

### 1. Build the contract

```bash
cd contract
scarb build
```

### 2. Set up your account

```bash
# Import an existing account
sncast account import \
  --name my-account \
  --address <YOUR_ACCOUNT_ADDRESS> \
  --private-key <YOUR_PRIVATE_KEY> \
  --type oz

# Or create and deploy a fresh account
sncast account create --name my-account --type oz
sncast account deploy --name my-account --fee-token eth
```

### 3. Declare the contract class

```bash
# ── Sepolia (testnet) ──
sncast --account my-account declare \
  --contract-name BCIAgentIdentity \
  --fee-token eth \
  --url https://free-rpc.nethermind.io/sepolia-juno

# ── Mainnet ──
sncast --account my-account declare \
  --contract-name BCIAgentIdentity \
  --fee-token strk \
  --url https://free-rpc.nethermind.io/mainnet-juno
```

Note the `class_hash` from the output.

### 4. Deploy the contract

The constructor takes two arguments: `owner` (admin) and `relayer` (the account that submits behavioral data).
For the demo, both can be the same account address.

```bash
# ── Sepolia (testnet) ──
sncast --account my-account deploy \
  --class-hash <CLASS_HASH_FROM_DECLARE> \
  --constructor-calldata <OWNER_ADDRESS> <RELAYER_ADDRESS> \
  --fee-token eth \
  --url https://free-rpc.nethermind.io/sepolia-juno

# ── Mainnet ──
sncast --account my-account deploy \
  --class-hash <CLASS_HASH_FROM_DECLARE> \
  --constructor-calldata <OWNER_ADDRESS> <RELAYER_ADDRESS> \
  --fee-token strk \
  --url https://free-rpc.nethermind.io/mainnet-juno
```

Copy the `contract_address` from the output — you'll add it to `.env` next.

### 5. Verify on Starkscan

| Network | URL |
|---|---|
| **Sepolia** | `https://sepolia.starkscan.co/contract/<CONTRACT_ADDRESS>` |
| **Mainnet** | `https://starkscan.co/contract/<CONTRACT_ADDRESS>` |

---

## 🔧 Environment Setup

```bash
cp .env.example .env
```

> 🚀 **Live Sepolia deployment available** — no need to deploy your own contract to get started.
> Use the address below and skip straight to running the demo:
>
> | | |
> |---|---|
> | **Network** | Starknet Sepolia |
> | **Contract** | `0x03d6466ad06b5eede41b1e6e257388ebe8f4bd9cb3be1d081b999fa35c0eb218` |
> | **Starkscan** | [View contract ↗](https://sepolia.starkscan.co/contract/0x03d6466ad06b5eede41b1e6e257388ebe8f4bd9cb3be1d081b999fa35c0eb218) |

Open `.env` and fill in:

```env
# ── Sepolia (testnet) ──────────────────────────────────────────
RPC_URL=https://free-rpc.nethermind.io/sepolia-juno
CONTRACT_ADDRESS=0x03d6466ad06b5eede41b1e6e257388ebe8f4bd9cb3be1d081b999fa35c0eb218
ACCOUNT_ADDRESS=0x<your_starknet_account>
PRIVATE_KEY=0x<your_private_key>

# ── Mainnet ────────────────────────────────────────────────────
# RPC_URL=https://free-rpc.nethermind.io/mainnet-juno
# CONTRACT_ADDRESS=0x<your_mainnet_contract_address>

# ── After complete_enrollment() confirms on-chain ─────────────
# (Leave blank on first run — the demo prints the candidate ID)
GLOBAL_AGENT_ID=my-agent-name    # or 0x<felt252>
```

> ⚠️ **Security:** Never commit `.env`. Add it to `.gitignore`. It contains your private key.

**`GLOBAL_AGENT_ID` notes:**
- Leave blank on first run — the demo prints the candidate ID at the end of the AGENT IDENTITY CARD
- Set it only after `complete_enrollment()` confirms on-chain (requires the 7-day window + ≥100 observations)
- Accepts a hex felt252 (`0x...`) or a friendly name (`my-agent`) — friendly names are deterministically hashed to felt252 via SHA-256

---

## 🏗️ Architecture — Dual-Process Model

```
┌──────────────────────────────────────────────────────────┐
│  Q-Process  (LLM Agent — Quarantined)                    │
│  ● Makes payment decisions                               │
│  ● Handles user interaction                              │
│  ● Has ZERO access to seed or Memory Secret              │
│  ● Can only send validated hex-64 nonces to P-Process    │
└──────────────────────┬───────────────────────────────────┘
                       │  nonce   (validated hex-64 only)
                       ▼  response (opaque hex token)
┌──────────────────────────────────────────────────────────┐
│  P-Process  (Privileged — NOT an LLM)                    │
│  ● Holds enrollment_response_seed in memory only         │
│  ● Computes poseidon(nonce, seed) for on-chain proof     │
│  ● IPC strictly rejects all non-hex input  (injection ✗) │
│  ● Blocks prompt injection at architectural level        │
└──────────────────────┬───────────────────────────────────┘
                       │  public verifiers only
                       ▼  (no secrets cross this boundary)
┌──────────────────────────────────────────────────────────┐
│  Starknet — BCIAgentIdentity.cairo  (Cairo v2)           │
│  ● enrollment_response_seed  (public on-chain)           │
│  ● ms_commitment              (public on-chain)          │
│  ● Challenge–response validated via Poseidon             │
│  ● Spending limits, lockouts, authorization rules        │
│  ● Full event audit trail: immutable, on-chain           │
└──────────────────────────────────────────────────────────┘
```

This follows the **CaMeL / DeepMind dual-agent pattern** applied to cryptographic identity. The LLM is architecturally isolated from all secrets — not by policy, but by process boundary.

---

## 🔒 Privacy Properties

**✅ Public on Starknet (anyone can read to verify):**
- `GlobalAgentID` — pseudonymous, unlinked to any real-world identity
- `enrollment_response_seed` — enables verification, **cannot** recover MS
- `ms_commitment` — proves MS binding, reveals nothing about MS value
- Behavioral tolerance bands — range parameters only, no raw observations
- Spending limits, lockout state, full authorization event history

**🔥 Never stored anywhere (destroyed at enrollment):**
- `K` — ephemeral secret key, zeroed after creating commitment
- `MS` — Memory Secret, zeroed after provisioning P-Process
- `B_stable` — raw 64-bit behavioral string (hidden inside `C = K XOR B`)
- Raw behavioral observations — processed in memory, never persisted

**Zero-knowledge properties:**
- Challenge-response proves *"agent knows MS"* — **not** the MS value itself
- Fuzzy commitment: `C = K XOR B` reveals nothing about `B` without `K`
- Behavioral confidence check proves behavioral match — not the actual feature values

---

## 🛡️ Security Fixes in v1.0

| # | Weakness | Fix Applied |
|---|---|---|
| **1** | 12-bit binary = 4,096 identities (brute-forceable in microseconds) | **64-bit = 2⁶⁴ identities** — 585 years to brute-force |
| **2** | BCH oracle attack via timing side-channel | `crypto.timingSafeEqual` + 24hr lockout after 3 failures |
| **3** | Memory Secret in LLM context window (prompt-injectable) | **Dual-Process Architecture** — P-Process holds seed, LLM never sees it |
| **4** | Model update locks agent out permanently | **EMA drift**: `F_new = 0.85×F_old + 0.15×F_current` — adapts gracefully |
| **5** | Critical math bug — verification equation never holds | **HMAC-based construction** — both sides derive the same value, always equal |
| **6** | Double-enrollment via orphaned temp agent ID | `complete_enrollment` invalidates temp ID atomically |
| **7** | `amount.try_into().unwrap()` panic DoS on large values | Replaced with `.expect('BCI: amount too large')` — clean revert |
| **8** | `update_template_drift` had no enrollment/revoke gate | Guard assertions added before any state changes |
| **9** | `request_reenrollment` on revoked agent creates stuck state | `assert(!is_revoked)` added before resetting enrollment |
| **10** | Same-day drift signature replay attack | `owner_signature` now binds to `template_version` |
| **11** | Zero-address accepted in constructor and `set_relayer` | `assert(!address.is_zero())` guards on all address inputs |
| **12** | `consecutive_low_conf` tracked but never acted upon | Triggers lockout + `SuspectedImpersonation` at 5 consecutive misses |

---

## 📁 Repo Structure

```
bci-starknet/
├── contract/
│   ├── src/
│   │   └── lib.cairo              ← Cairo v2 contract (BCIAgentIdentity)
│   └── Scarb.toml                 ← Cairo package manifest
├── src/
│   ├── demo.js                    ← Full on-chain demo (real Starknet Sepolia)
│   └── test_crypto.js             ← Crypto unit tests
├── .env.example                   ← Environment variable template
├── package.json
└── README.md
```

---

## 🗺️ Milestones & Roadmap

BCI is an active, evolving research project. Here is where we are and where we're going:

### ✅ v1.0 — Completed
- [x] 64-bit behavioral identity space (2⁶⁴ identities)
- [x] Fuzzy commitment scheme (XOR-based, ZK-hiding)
- [x] HMAC Memory Secret derivation and P-Process architecture
- [x] EMA drift adaptation — model upgrades don't lock agents out
- [x] Full Cairo v2 on-chain contract with OZ components
- [x] On-chain challenge–response (Poseidon verification)
- [x] Sustained low-confidence lockout (impersonation detection)
- [x] Real Starknet Sepolia demo with full event audit trail
- [x] Comprehensive security review — 12 vulnerabilities identified and fixed

### 🔨 v1.x — In Progress
- [ ] **Specialized BCI SDK** — standalone SDK any platform can import to add behavioral identity to their AI agents without reimplementing the protocol from scratch
- [ ] **Multi-chain verifier** — verify BCI identity proofs across chains (Ethereum, Base) by bridging commitment hashes via Starknet's SNOS
- [ ] **Off-chain enrollment acceleration** — STARK proof of enrollment validity to cryptographically compress the 7-day window
- [ ] **Merkle identity registry** — batch many agents into a single on-chain root for cheaper enrollment verification at scale
- [ ] **ZionDefi Card pilot** — full integration with ZionDefi smart cards where agents are card owners, spending real funds on Mainnet

### 🚀 v2.0 — Planned (Fully Starknet-Native)
- [ ] **On-chain STARK proofs for behavioral scoring** — replace off-chain confidence computation with a verifiable STARK proof submitted by the relayer
- [ ] **BCI Identity NFT** — enrollment creates a soul-bound on-chain artifact representing the agent's behavioral commitment
- [ ] **Social recovery** — multi-sig owner re-enrollment if the Memory Secret is lost
- [ ] **BCI DAO governance** — confidence thresholds, lockout durations, drift limits governed on-chain
- [ ] **Agent reputation scoring** — cumulative on-chain reputation built from authorization history and behavioral consistency
- [ ] **Hardware-backed P-Process** — optional TEE/SGX integration for highest-security deployments 
- [ ] **BCI Indexer** — dedicated indexing layer for querying agent authorization history and drift events
- [ ] **Developer portal** — hosted dashboard for monitoring enrolled agents, viewing events, and managing auth keys

### 💡 Research Ideas Under Consideration
- **Federated enrollment** — distribute observation collection across multiple servers with ZK aggregation proofs
- **Behavioral graph analysis** — model behavioral sequences as a directed graph for richer fingerprinting than flat feature vectors
- **LLM-agnostic adapters** — BCI feature extractors for GPT, Claude, Llama and other architectures
- **Differential privacy for feature vectors** — add calibrated noise to stored tolerances to prevent reverse-engineering of raw behavior
- **Threshold enrollment** — allow a quorum of independent observers to co-sign enrollment for higher assurance

---

## 🔮 V2 Preview

> **V2 is in early design. Everything is Starknet-native.**

V2 replaces off-chain behavioral scoring with **on-chain STARK proofs**. The relayer submits a proof that the agent's current behavioral vector falls within the enrolled tolerance bands — no trusted behavioral score, no relayer assumption. The contract verifies the proof directly using Starknet's native proving infrastructure.

V2 also introduces the **BCI Identity NFT**: enrollment creates a non-fungible, soul-bound on-chain artifact representing the agent's behavioral commitment. It cannot be transferred but can be updated via the drift mechanism as the agent's model evolves.

The architecture becomes fully trustless: Starknet enforces both the identity check and the spending rules, with zero off-chain oracles.

**V2 is being built entirely on Starknet. We are committed to this chain.**

---

## 🤝 Contributing

Contributions are very welcome! BCI is a research project and we want the broader community involved in shaping where it goes.

```bash
# Fork the repo, then:
git clone https://github.com/<your-username>/bci-starknet
cd bci-starknet
npm install
node src/test_crypto.js    # make sure all tests pass before making changes
```

**Ways to contribute:**
- 🐛 **Bug reports** — open a GitHub issue with clear reproduction steps
- 🔒 **Security findings** — email `manomitehq@gmail.com` directly (please do NOT open public issues for security vulnerabilities)
- 🧪 **Test coverage** — add unit or integration tests for the Cairo contract and JS crypto core
- 📖 **Documentation** — improve explanations, add architecture diagrams, translate
- 💡 **Feature proposals** — open a discussion or issue with your idea
- 🏗️ **SDK development** — help build the specialized BCI SDK (see Milestones)
- 🔬 **Research collaboration** — cite the paper, build on the protocol, propose joint work

All contributors will be credited. Pull requests are reviewed promptly.

---

## 📚 Citation & Research Use

This repository accompanies a **peer-reviewed research publication**. If you use BCI in your work, project, product, or academic paper, please cite it:

```bibtex
@misc{bci_starknet_2026,
  author       = {Adeyeye George},
  title        = {BCI — Behavioral Commitment Identity on Starknet},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.18888283},
  url          = {https://zenodo.org/records/18888283},
  note         = {ZionDefi Research — Zero-knowledge AI agent identity without stored credentials}
}
```

📄 **Research paper:** [https://zenodo.org/records/18888283](https://zenodo.org/records/18888283)

Academic collaboration, protocol reviews, and joint research proposals are very welcome. Reach out at [manomitehq@gmail.com](mailto:manomitehq@gmail.com).

---

## 💛 Sponsorship

BCI is an independent research project maintained by a small, dedicated team. If this work is valuable to your platform, company, or research group and you'd like to support continued development and the V2 roadmap, we'd love to hear from you.

**Sponsorship helps fund:**
- 🔬 V2 STARK proof circuit development
- 🧰 BCI SDK engineering and open-source maintenance
- 🔐 Professional smart contract security audits
- 🌐 Multi-chain integration work
- 📖 Academic publication of V2 research

📧 **Contact us:** [manomitehq@gmail.com](mailto:manomitehq@gmail.com)

All sponsors will be recognized prominently in the repository, demo, and research publications.

---

## ⚠️ Disclaimer

> **This is an experimental research project. It has not been audited.**

BCI v1.0 was developed as part of the Re{define} hackathon and as a published research prototype for the ZionDefi smart card system. It has **not** been reviewed by a professional smart contract security firm.

- ❌ **Do not deploy to Mainnet with real funds without a full professional security audit**
- ❌ **Do not use in any production system without thorough independent review**
- ✅ Use freely for research, learning, experimentation, and testnet development
- ✅ Build on the ideas, cite the paper, extend and improve the protocol

The behavioral confidence thresholds, lockout parameters, and cryptographic constructions are research-grade implementations designed to demonstrate the protocol — not to serve as production-hardened security infrastructure.

**By using this code, you accept full responsibility for any outcomes.** The authors and ZionDefi Research provide no warranty, express or implied, of any kind.

---

## 👤 Author

**Adeyeye George**
ZionDefi Research · Manomite Limited · Lagos, Nigeria 🇳🇬

| | |
|---|---|
| 📧 Email | [manomitehq@gmail.com](mailto:manomitehq@gmail.com) |
| 🐙 GitHub | [github.com/mitmelon](https://github.com/mitmelon) |
| 📄 Research | [zenodo.org/records/18888283](https://zenodo.org/records/18888283) |

---

<div align="center">

*BCI is the identity primitive that the AI payments ecosystem has been missing.*

*The agent from the Lagos server is still the same agent in Canada —*
*provably, privately, on Starknet.*

<br/>

**⭐ Star this repo · 🍴 Fork it · 📖 Cite the paper · 🤝 Contribute**

<br/>

[![Starknet](https://img.shields.io/badge/Powered%20by-Starknet-blueviolet?logo=ethereum)](https://starknet.io/)
[![Cairo](https://img.shields.io/badge/Written%20in-Cairo%20v2-orange)](https://book.cairo-lang.org/)
[![ZionDefi](https://img.shields.io/badge/Built%20for-ZionDefi%20Smart%20Cards-green)](https://github.com/mitmelon/bci-starknet)

</div>