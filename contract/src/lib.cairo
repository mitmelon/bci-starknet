// ================================================================
// BCI v1.0.0 — Behavioral Commitment Identity Contract
// ================================================================
// Author:          Adeyeye George
// Project:         ZionDefi Research
// Company:         Manomite Limited
// Version:         1.0.0
// ================================================================
//
// OpenZeppelin components used (v0.19.0):
//   • OwnableComponent         — admin ownership (transfer, renounce)
//   • PausableComponent        — emergency halt on auth / enrollment
//   • ReentrancyGuardComponent — re-entrancy protection on auth flow
//   • UpgradeableComponent     — UUPS upgrade (owner-only)
// ================================================================

use starknet::ContractAddress;
use starknet::ClassHash;

// ================================================================
// CONSTANTS
// ================================================================
const BCI_VERSION: felt252           = '1.0.0';
const BINARY_STRING_BITS: u32        = 64;
const ENROLLMENT_PERIOD_SECS: u64    = 604800;   // 7 days
const MIN_OBSERVATIONS: u32          = 100;
const MAX_ENROLLMENT_EXTENSIONS: u32 = 13;        // ~3 months max
const MIN_VARIANCE_MAD: u64          = 1;         // at least 1 unit of spread
const CHALLENGE_EXPIRY_SECS: u64     = 60;
const MAX_FAILURES: u32              = 3;
const LOCKOUT_DURATION_SECS: u64     = 86400;
const DRIFT_ALERT_SIGMA_X100: u64    = 200;
const DAILY_SECS: u64                = 86400;

// Confidence thresholds (×100 for integer math)
const CONFIDENCE_HIGH: u64 = 85;
const CONFIDENCE_MED: u64  = 60;

// ================================================================
// DATA STRUCTURES
// ================================================================

#[derive(Drop, Serde, starknet::Store)]
struct BCITemplate {
    // ── Fuzzy commitment ──────────────────────────────────────
    // C = BCH_encode(K) XOR B_stable_64
    // commitment_hash = HMAC(K, "CommitmentHash:" + hex(C))
    commitment_hash: felt252,

    // ── 64-bit behavioral feature vector ─────────────────────
    // Stored as two felt252 values (high 32 bits + low 32 bits)
    binary_high: felt252,
    binary_low:  felt252,

    // Stable feature centers (scaled ×10000)
    f1_interval_med:   u64,
    f2_interval_mad:   u64,
    f3_payload_med:    u64,
    f4_payload_mad:    u64,
    f5_tokens_med:     u64,
    f6_tokens_mad:     u64,
    f7_peak_hour:      u64,
    f8_auth_freq:      u64,
    f9_retry_med:      u64,
    f10_amount_med:    u64,
    f11_resp_time_med: u64,
    f12_hdr_count_med: u64,
    f13_minute_bucket: u64,

    // Hash-type features
    f14_header_pattern: felt252,
    f15_endpoint_seq:   felt252,
    f16_merchant_pat:   felt252,
    f17_ua_hash:        felt252,

    // Tolerance bands (scaled ×10000)
    tol_f1:  u64,
    tol_f3:  u64,
    tol_f5:  u64,
    tol_f7:  u64,
    tol_f9:  u64,
    tol_f10: u64,
    tol_f11: u64,
    tol_f12: u64,

    // enrollment_response_seed = HMAC(MS, "BCI_RESPONSE_SEED")
    // Stored on-chain. Cannot be reversed to recover MS.
    enrollment_response_seed: felt252,

    // ms_commitment = HMAC(MS, "BCI_COMMITMENT")
    ms_commitment: felt252,

    // ms_receipt_verifier = HMAC(MS, "BCI_MS_RECEIPT")
    ms_receipt_verifier: felt252,

    // ── Metadata ─────────────────────────────────────────────
    enrollment_timestamp: u64,
    observation_count:    u32,
    template_version:     u32,
    last_drift_update:    u64,
    is_active:            bool,
}

#[derive(Drop, Serde, starknet::Store)]
struct AgentRegistration {
    agent_id:     felt252,
    owner_wallet: ContractAddress,
    card_contract: ContractAddress,

    // Spending rules
    high_conf_daily_limit: u256,
    med_conf_daily_limit:  u256,

    // Auth key
    current_auth_key_hash: felt252,
    auth_key_expiry:       u64,

    // Enrollment state
    enrollment_complete: bool,
    enrollment_start:    u64,
    ms_provisioned:      bool,
    enrollment_extensions: u32,

    challenge_failure_count:   u32,
    behavioral_failure_count:  u32,
    locked_until:              u64,
    total_challenges_issued:   u64,
    total_challenges_passed:   u64,

    // Active challenge state
    active_nonce:     felt252,
    nonce_expiry:     u64,
    nonce_amount:     u256,
    nonce_merchant:   ContractAddress,
    nonce_conf_score: u64,
    challenge_active: bool,

    // Spending state
    daily_spent:    u256,
    last_spend_day: u64,

    // Status
    is_revoked:    bool,
    revoke_reason: felt252,

    // Monitoring
    last_conf_score:      u64,
    consecutive_low_conf: u32,
    total_transactions:   u64,
    flagged_transactions: u64,
}

#[derive(Drop, Serde)]
struct ChallengeIssuance {
    nonce:      felt252,
    expires_at: u64,
}

#[derive(Drop, Serde)]
struct AuthResult {
    approved:        bool,
    conf_score:      u64,
    spending_limit:  u256,
    flag_owner:      bool,
    needs_challenge: bool,
    challenge:       ChallengeIssuance,
    reason:          felt252,
}

// ================================================================
// CONTRACT INTERFACE
// ================================================================

#[starknet::interface]
trait IBCIAgentIdentity<TContractState> {

    // ── Admin / upgrade ────────────────────────────────────────
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn set_relayer(ref self: TContractState, new_relayer: ContractAddress);
    fn get_relayer(self: @TContractState) -> ContractAddress;

    // ── Enrollment ─────────────────────────────────────────────
    fn begin_enrollment(
        ref self: TContractState,
        card_contract:         ContractAddress,
        high_conf_daily_limit: u256,
        med_conf_daily_limit:  u256,
    ) -> felt252;

    fn submit_observation_batch(
        ref self: TContractState,
        agent_id:          felt252,
        observation_hash:  felt252,
        observation_count: u32,
    );

    fn complete_enrollment(
        ref self: TContractState,
        agent_id:                 felt252,
        global_agent_id:          felt252,
        commitment_hash:          felt252,
        binary_high:              felt252,
        binary_low:               felt252,
        enrollment_response_seed: felt252,
        ms_commitment:            felt252,
        ms_receipt_verifier:      felt252,
        template:                 BCITemplate,
        auth_key_hash:            felt252,
    );

    fn extend_enrollment(ref self: TContractState, agent_id: felt252);

    fn confirm_ms_provisioned(
        ref self: TContractState,
        agent_id:   felt252,
        ms_receipt: felt252,
    );

    // ── Authorization ─────────────────────────────────────────
    fn request_authorization(
        ref self: TContractState,
        agent_id:         felt252,
        auth_key_hash:    felt252,
        behavioral_score: u64,
        score_proof:      felt252,
        amount:           u256,
        merchant:         ContractAddress,
    ) -> AuthResult;

    fn submit_challenge_response(
        ref self: TContractState,
        agent_id:       felt252,
        nonce:          felt252,
        response_hash:  felt252,
        response_valid: bool,
    ) -> AuthResult;

    fn update_template_drift(
        ref self: TContractState,
        agent_id:         felt252,
        new_template:     BCITemplate,
        drift_sigma_x100: u64,
        owner_signature:  felt252,
    );

    // ── Cross-server verification ─────────────────────────────
    fn verify_global_identity(
        self:             @TContractState,
        agent_id:         felt252,
        behavioral_score: u64,
        response_valid:   bool,
    ) -> bool;

    // ── Key management ────────────────────────────────────────
    fn rotate_auth_key(
        ref self: TContractState,
        agent_id:     felt252,
        new_key_hash: felt252,
        new_expiry:   u64,
    );

    fn request_reenrollment(ref self: TContractState, agent_id: felt252);
    fn revoke_agent(ref self: TContractState, agent_id: felt252, reason: felt252);

    fn update_spending_limits(
        ref self: TContractState,
        agent_id:              felt252,
        high_conf_daily_limit: u256,
        med_conf_daily_limit:  u256,
    );

    // ── Views ─────────────────────────────────────────────────
    fn get_agent(self: @TContractState, agent_id: felt252) -> AgentRegistration;
    fn get_template(self: @TContractState, agent_id: felt252) -> BCITemplate;
    fn has_global_identity(self: @TContractState, agent_id: felt252) -> bool;
    fn is_locked_out(self: @TContractState, agent_id: felt252) -> bool;
    fn get_enrollment_response_seed(self: @TContractState, agent_id: felt252) -> felt252;
}

// ================================================================
// CONTRACT IMPLEMENTATION
// ================================================================

#[starknet::contract]
mod BCIAgentIdentity {
    use super::{
        BCITemplate, AgentRegistration, ChallengeIssuance, AuthResult,
        IBCIAgentIdentity, ContractAddress, ClassHash,
        BCI_VERSION, ENROLLMENT_PERIOD_SECS,
        MIN_OBSERVATIONS, MAX_ENROLLMENT_EXTENSIONS, MIN_VARIANCE_MAD,
        CHALLENGE_EXPIRY_SECS, MAX_FAILURES,
        LOCKOUT_DURATION_SECS, DRIFT_ALERT_SIGMA_X100,
        DAILY_SECS, CONFIDENCE_HIGH, CONFIDENCE_MED,
        BINARY_STRING_BITS,
    };
    use starknet::{get_caller_address, get_block_timestamp};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StoragePathEntry,
    };
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;

    // ── OpenZeppelin components ───────────────────────────────
    use openzeppelin_access::ownable::OwnableComponent;
    use openzeppelin_security::pausable::PausableComponent;
    use openzeppelin_security::reentrancyguard::ReentrancyGuardComponent;
    use openzeppelin_upgrades::UpgradeableComponent;
    use openzeppelin_upgrades::interface::IUpgradeable;

    component!(path: OwnableComponent,         storage: ownable,          event: OwnableEvent);
    component!(path: PausableComponent,        storage: pausable,         event: PausableEvent);
    component!(path: ReentrancyGuardComponent, storage: reentrancy_guard, event: ReentrancyGuardEvent);
    component!(path: UpgradeableComponent,     storage: upgradeable,      event: UpgradeableEvent);

    // Ownable + Pausable expose their ABI publicly
    #[abi(embed_v0)]
    impl OwnableMixinImpl   = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl PausableImpl        = PausableComponent::PausableImpl<ContractState>;
    impl PausableInternalImpl = PausableComponent::InternalImpl<ContractState>;

    // ReentrancyGuard + Upgradeable are internal only
    impl ReentrancyGuardInternalImpl = ReentrancyGuardComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl     = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        // ── OZ substorage slots ───────────────────────────────
        #[substorage(v0)]
        ownable:          OwnableComponent::Storage,
        #[substorage(v0)]
        pausable:         PausableComponent::Storage,
        #[substorage(v0)]
        reentrancy_guard: ReentrancyGuardComponent::Storage,
        #[substorage(v0)]
        upgradeable:      UpgradeableComponent::Storage,

        // ── BCI-specific storage ──────────────────────────────
        relayer:         ContractAddress,
        agents:          starknet::storage::Map<felt252, AgentRegistration>,
        templates:       starknet::storage::Map<felt252, BCITemplate>,
        obs_count:       starknet::storage::Map<felt252, u32>,
        obs_chain_hash:  starknet::storage::Map<felt252, felt252>,
        owner_count:     starknet::storage::Map<ContractAddress, u32>,
        owner_agents:    starknet::storage::Map<(ContractAddress, u32), felt252>,
    }

    // ── Events ────────────────────────────────────────────────
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // OZ component events (flattened)
        #[flat]
        OwnableEvent:          OwnableComponent::Event,
        #[flat]
        PausableEvent:         PausableComponent::Event,
        #[flat]
        ReentrancyGuardEvent:  ReentrancyGuardComponent::Event,
        #[flat]
        UpgradeableEvent:      UpgradeableComponent::Event,

        // BCI-specific events
        RelayerUpdated:          RelayerUpdated,
        EnrollmentStarted:       EnrollmentStarted,
        EnrollmentCompleted:     EnrollmentCompleted,
        EnrollmentExtended:      EnrollmentExtended,
        MSProvisioned:           MSProvisioned,
        ChallengeIssued:         ChallengeIssued,
        ChallengePassed:         ChallengePassed,
        ChallengeFailed:         ChallengeFailed,
        AgentLockedOut:          AgentLockedOut,
        TemplateDriftUpdated:    TemplateDriftUpdated,
        MajorDriftDetected:      MajorDriftDetected,
        TransactionAuthorized:   TransactionAuthorized,
        TransactionBlocked:      TransactionBlocked,
        AgentFlagged:            AgentFlagged,
        AgentRevoked:            AgentRevoked,
        AuthKeyRotated:          AuthKeyRotated,
        ReenrollmentRequested:   ReenrollmentRequested,
        SuspectedImpersonation:  SuspectedImpersonation,
    }

    #[derive(Drop, starknet::Event)]
    struct RelayerUpdated {
        #[key] old_relayer: ContractAddress,
        #[key] new_relayer: ContractAddress,
    }
    #[derive(Drop, starknet::Event)]
    struct EnrollmentStarted {
        #[key] agent_id: felt252,
        #[key] owner:    ContractAddress,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct EnrollmentCompleted {
        #[key] agent_id:     felt252,
        global_agent_id:     felt252,
        commitment_hash:     felt252,
        binary_bits:         u32,
        timestamp:           u64,
    }
    #[derive(Drop, starknet::Event)]
    struct EnrollmentExtended {
        #[key] agent_id:  felt252,
        #[key] owner:     ContractAddress,
        extension_count:  u32,
        new_deadline:     u64,
        timestamp:        u64,
    }
    #[derive(Drop, starknet::Event)]
    struct MSProvisioned {
        #[key] agent_id: felt252,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct ChallengeIssued {
        #[key] agent_id: felt252,
        nonce:           felt252,
        expires_at:      u64,
    }
    #[derive(Drop, starknet::Event)]
    struct ChallengePassed {
        #[key] agent_id: felt252,
        amount:          u256,
        conf_score:      u64,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct ChallengeFailed {
        #[key] agent_id: felt252,
        #[key] owner:    ContractAddress,
        failure_count:   u32,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct AgentLockedOut {
        #[key] agent_id: felt252,
        #[key] owner:    ContractAddress,
        locked_until:    u64,
        reason:          felt252,
    }
    #[derive(Drop, starknet::Event)]
    struct TemplateDriftUpdated {
        #[key] agent_id:  felt252,
        drift_sigma_x100: u64,
        new_version:      u32,
        timestamp:        u64,
    }
    #[derive(Drop, starknet::Event)]
    struct MajorDriftDetected {
        #[key] agent_id:  felt252,
        #[key] owner:     ContractAddress,
        drift_sigma_x100: u64,
        timestamp:        u64,
    }
    #[derive(Drop, starknet::Event)]
    struct TransactionAuthorized {
        #[key] agent_id: felt252,
        amount:          u256,
        conf_score:      u64,
        merchant:        ContractAddress,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct TransactionBlocked {
        #[key] agent_id: felt252,
        amount:          u256,
        reason:          felt252,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct AgentFlagged {
        #[key] agent_id: felt252,
        #[key] owner:    ContractAddress,
        conf_score:      u64,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct AgentRevoked {
        #[key] agent_id: felt252,
        #[key] owner:    ContractAddress,
        reason:          felt252,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct AuthKeyRotated {
        #[key] agent_id: felt252,
        new_expiry:      u64,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct ReenrollmentRequested {
        #[key] agent_id: felt252,
        #[key] owner:    ContractAddress,
        timestamp:       u64,
    }
    #[derive(Drop, starknet::Event)]
    struct SuspectedImpersonation {
        #[key] agent_id:  felt252,
        #[key] owner:     ContractAddress,
        failure_count:    u32,
        timestamp:        u64,
    }

    // ── Constructor ───────────────────────────────────────────
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner:   ContractAddress,
        relayer: ContractAddress,
    ) {
        self.ownable.initializer(owner);
        self.relayer.write(relayer);
    }

    // ── Internal helpers ──────────────────────────────────────
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_relayer(self: @ContractState) {
            assert(get_caller_address() == self.relayer.read(), 'BCI: only relayer');
        }
        fn _only_agent_owner(self: @ContractState, agent_id: felt252) {
            let agent = self.agents.entry(agent_id).read();
            assert(get_caller_address() == agent.owner_wallet, 'BCI: only agent owner');
        }
        fn _not_locked(self: @ContractState, agent_id: felt252) {
            let agent = self.agents.entry(agent_id).read();
            assert(
                get_block_timestamp() >= agent.locked_until,
                'BCI: agent locked out'
            );
        }
        fn _apply_lockout(ref self: ContractState, agent_id: felt252, reason: felt252) {
            let mut agent = self.agents.entry(agent_id).read();
            let owner = agent.owner_wallet;
            let until = get_block_timestamp() + LOCKOUT_DURATION_SECS;
            agent.locked_until = until;
            self.agents.entry(agent_id).write(agent);
            self.emit(AgentLockedOut { agent_id, owner, locked_until: until, reason });
        }
    }

    // ── BCI implementation ────────────────────────────────────
    #[abi(embed_v0)]
    impl BCIAgentIdentityImpl of IBCIAgentIdentity<ContractState> {
        // ── Admin / upgrade ───────────────────────────────────

        fn pause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.pause();
        }

        fn unpause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.unpause();
        }

        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(new_class_hash);
        }

        fn set_relayer(ref self: ContractState, new_relayer: ContractAddress) {
            self.ownable.assert_only_owner();
            let old_relayer = self.relayer.read();
            self.relayer.write(new_relayer);
            self.emit(RelayerUpdated { old_relayer, new_relayer });
        }

        fn get_relayer(self: @ContractState) -> ContractAddress {
            self.relayer.read()
        }

        // ── Enrollment ────────────────────────────────────────

        fn begin_enrollment(
            ref self: ContractState,
            card_contract:         ContractAddress,
            high_conf_daily_limit: u256,
            med_conf_daily_limit:  u256,
        ) -> felt252 {
            self.pausable.assert_not_paused();
            let caller    = get_caller_address();
            let timestamp = get_block_timestamp();

            let mut id_input: Array<felt252> = ArrayTrait::new();
            id_input.append(caller.into());
            id_input.append(timestamp.into());
            id_input.append(BCI_VERSION);
            let temp_id = poseidon_hash_span(id_input.span());

            let reg = AgentRegistration {
                agent_id:                temp_id,
                owner_wallet:            caller,
                card_contract,
                high_conf_daily_limit,
                med_conf_daily_limit,
                current_auth_key_hash:   0,
                auth_key_expiry:         0,
                enrollment_complete:     false,
                enrollment_start:        timestamp,
                ms_provisioned:          false,
                enrollment_extensions:   0,
                challenge_failure_count:  0,
                behavioral_failure_count: 0,
                locked_until:            0,
                total_challenges_issued: 0,
                total_challenges_passed: 0,
                active_nonce:            0,
                nonce_expiry:            0,
                nonce_amount:            0,
                nonce_merchant:          caller,
                nonce_conf_score:        0,
                challenge_active:        false,
                daily_spent:             0,
                last_spend_day:          0,
                is_revoked:              false,
                revoke_reason:           0,
                last_conf_score:         0,
                consecutive_low_conf:    0,
                total_transactions:      0,
                flagged_transactions:    0,
            };

            self.agents.entry(temp_id).write(reg);
            self.obs_count.entry(temp_id).write(0);

            let count = self.owner_count.entry(caller).read();
            self.owner_agents.entry((caller, count)).write(temp_id);
            self.owner_count.entry(caller).write(count + 1);

            self.emit(EnrollmentStarted { agent_id: temp_id, owner: caller, timestamp });
            temp_id
        }

        fn submit_observation_batch(
            ref self: ContractState,
            agent_id:          felt252,
            observation_hash:  felt252,
            observation_count: u32,
        ) {
            self._only_relayer();
            let agent = self.agents.entry(agent_id).read();
            assert(!agent.enrollment_complete, 'BCI: already enrolled');
            assert(!agent.is_revoked, 'BCI: revoked');

            let prev_count = self.obs_count.entry(agent_id).read();
            let prev_hash  = self.obs_chain_hash.entry(agent_id).read();

            let mut chain: Array<felt252> = ArrayTrait::new();
            chain.append(prev_hash);
            chain.append(observation_hash);
            chain.append(observation_count.into());
            let new_hash = poseidon_hash_span(chain.span());

            self.obs_count.entry(agent_id).write(prev_count + observation_count);
            self.obs_chain_hash.entry(agent_id).write(new_hash);
        }

        fn complete_enrollment(
            ref self: ContractState,
            agent_id:                 felt252,
            global_agent_id:          felt252,
            commitment_hash:          felt252,
            binary_high:              felt252,
            binary_low:               felt252,
            enrollment_response_seed: felt252,
            ms_commitment:            felt252,
            ms_receipt_verifier:      felt252,
            template:                 BCITemplate,
            auth_key_hash:            felt252,
        ) {
            self._only_relayer();
            let mut agent = self.agents.entry(agent_id).read();
            assert(!agent.enrollment_complete, 'BCI: already enrolled');
            assert(!agent.is_revoked, 'BCI: revoked');

            let obs_count = self.obs_count.entry(agent_id).read();
            assert(obs_count >= MIN_OBSERVATIONS, 'BCI: insufficient observations');

            let timestamp = get_block_timestamp();
            let required_elapsed = ENROLLMENT_PERIOD_SECS
                * (agent.enrollment_extensions + 1).into();
            assert(
                timestamp >= agent.enrollment_start + required_elapsed,
                'BCI: enrollment window open'
            );

            // Data sufficiency gates
            assert(template.f2_interval_mad >= MIN_VARIANCE_MAD, 'BCI: no latency variance');
            assert(template.f4_payload_mad  >= MIN_VARIANCE_MAD, 'BCI: no token variance');
            assert(template.f6_tokens_mad   >= MIN_VARIANCE_MAD, 'BCI: no amount variance');
            assert(template.tol_f1 > 0, 'BCI: zero latency tolerance');
            assert(template.tol_f3 > 0, 'BCI: zero token tolerance');
            assert(template.tol_f5 > 0, 'BCI: zero amount tolerance');

            let mut t = template;
            t.commitment_hash          = commitment_hash;
            t.binary_high              = binary_high;
            t.binary_low               = binary_low;
            t.enrollment_response_seed = enrollment_response_seed;
            t.ms_commitment            = ms_commitment;
            t.ms_receipt_verifier      = ms_receipt_verifier;
            t.enrollment_timestamp     = timestamp;
            t.observation_count        = obs_count;
            t.template_version         = 1;
            t.last_drift_update        = timestamp;
            t.is_active                = true;
            self.templates.entry(global_agent_id).write(t);

            agent.agent_id              = global_agent_id;
            agent.enrollment_complete   = true;
            agent.ms_provisioned        = false;
            agent.current_auth_key_hash = auth_key_hash;
            agent.auth_key_expiry       = timestamp + DAILY_SECS;
            self.agents.entry(global_agent_id).write(agent);

            self.emit(EnrollmentCompleted {
                agent_id: global_agent_id,
                global_agent_id,
                commitment_hash,
                binary_bits: BINARY_STRING_BITS,
                timestamp,
            });
        }

        fn extend_enrollment(ref self: ContractState, agent_id: felt252) {
            self._only_relayer();
            let mut agent = self.agents.entry(agent_id).read();
            assert(!agent.enrollment_complete, 'BCI: already enrolled');
            assert(!agent.is_revoked, 'BCI: revoked');
            assert(
                agent.enrollment_extensions < MAX_ENROLLMENT_EXTENSIONS,
                'BCI: max extensions reached'
            );

            let timestamp = get_block_timestamp();
            let current_deadline = agent.enrollment_start
                + ENROLLMENT_PERIOD_SECS * (agent.enrollment_extensions + 1).into();
            assert(timestamp >= current_deadline, 'BCI: window still open');

            agent.enrollment_extensions += 1;
            let new_deadline = agent.enrollment_start
                + ENROLLMENT_PERIOD_SECS * (agent.enrollment_extensions + 1).into();
            let owner    = agent.owner_wallet;
            let ext_count = agent.enrollment_extensions;
            self.agents.entry(agent_id).write(agent);

            self.emit(EnrollmentExtended {
                agent_id,
                owner,
                extension_count: ext_count,
                new_deadline,
                timestamp,
            });
        }

        fn confirm_ms_provisioned(
            ref self: ContractState,
            agent_id:   felt252,
            ms_receipt: felt252,
        ) {
            self._only_relayer();
            let template = self.templates.entry(agent_id).read();
            let mut agent = self.agents.entry(agent_id).read();
            assert(ms_receipt == template.ms_receipt_verifier, 'BCI: invalid MS receipt');
            agent.ms_provisioned = true;
            self.agents.entry(agent_id).write(agent);
            self.emit(MSProvisioned { agent_id, timestamp: get_block_timestamp() });
        }

        // ── Authorization ─────────────────────────────────────

        fn request_authorization(
            ref self: ContractState,
            agent_id:         felt252,
            auth_key_hash:    felt252,
            behavioral_score: u64,
            score_proof:      felt252,
            amount:           u256,
            merchant:         ContractAddress,
        ) -> AuthResult {
            self.reentrancy_guard.start();
            self._only_relayer();
            self.pausable.assert_not_paused();

            let mut agent = self.agents.entry(agent_id).read();
            let timestamp = get_block_timestamp();
            let empty_challenge = ChallengeIssuance { nonce: 0, expires_at: 0 };

            if agent.is_revoked {
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: 0, spending_limit: 0, flag_owner: true,  needs_challenge: false, challenge: empty_challenge, reason: 'REVOKED' };
            }
            if !agent.enrollment_complete {
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: 0, spending_limit: 0, flag_owner: false, needs_challenge: false, challenge: empty_challenge, reason: 'NOT_ENROLLED' };
            }
            if !agent.ms_provisioned {
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: 0, spending_limit: 0, flag_owner: false, needs_challenge: false, challenge: empty_challenge, reason: 'MS_NOT_PROVISIONED' };
            }
            if timestamp < agent.locked_until {
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: 0, spending_limit: 0, flag_owner: true,  needs_challenge: false, challenge: empty_challenge, reason: 'LOCKED_OUT' };
            }

            if auth_key_hash != agent.current_auth_key_hash {
                agent.challenge_failure_count += 1;
                if agent.challenge_failure_count >= MAX_FAILURES {
                    agent.locked_until = timestamp + LOCKOUT_DURATION_SECS;
                    let owner = agent.owner_wallet;
                    let locked_until = agent.locked_until;
                    self.agents.entry(agent_id).write(agent);
                    self.emit(AgentLockedOut { agent_id, owner, locked_until, reason: 'INVALID_AUTH_KEY' });
                } else {
                    self.agents.entry(agent_id).write(agent);
                }
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: behavioral_score, spending_limit: 0, flag_owner: true, needs_challenge: false, challenge: empty_challenge, reason: 'INVALID_AUTH_KEY' };
            }

            if timestamp > agent.auth_key_expiry {
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: behavioral_score, spending_limit: 0, flag_owner: true, needs_challenge: false, challenge: empty_challenge, reason: 'AUTH_KEY_EXPIRED' };
            }

            let mut proof_data: Array<felt252> = ArrayTrait::new();
            proof_data.append(agent_id);
            proof_data.append(behavioral_score.into());
            proof_data.append(timestamp.into());
            let expected_proof = poseidon_hash_span(proof_data.span());
            assert(score_proof == expected_proof, 'BCI: invalid score proof');

            if behavioral_score < CONFIDENCE_MED {
                agent.behavioral_failure_count += 1;
                agent.consecutive_low_conf += 1;
                if agent.behavioral_failure_count >= MAX_FAILURES {
                    agent.locked_until = timestamp + LOCKOUT_DURATION_SECS;
                    let owner = agent.owner_wallet;
                    let locked_until = agent.locked_until;
                    let bfail = agent.behavioral_failure_count;
                    self.agents.entry(agent_id).write(agent);
                    self.emit(AgentLockedOut { agent_id, owner, locked_until, reason: 'LOW_BEHAVIORAL_CONFIDENCE' });
                    self.emit(SuspectedImpersonation { agent_id, owner, failure_count: bfail, timestamp });
                    self.reentrancy_guard.end();
                    return AuthResult { approved: false, conf_score: behavioral_score, spending_limit: 0, flag_owner: true, needs_challenge: false, challenge: empty_challenge, reason: 'LOCKED_OUT' };
                }
                self.agents.entry(agent_id).write(agent);
                self.emit(TransactionBlocked { agent_id, amount, reason: 'LOW_BEHAVIORAL_CONFIDENCE', timestamp });
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: behavioral_score, spending_limit: 0, flag_owner: true, needs_challenge: false, challenge: empty_challenge, reason: 'LOW_BEHAVIORAL_CONFIDENCE' };
            }

            // Issue challenge
            let mut nonce_data: Array<felt252> = ArrayTrait::new();
            nonce_data.append(agent_id);
            nonce_data.append(timestamp.into());
            nonce_data.append(amount.try_into().unwrap());
            let nonce      = poseidon_hash_span(nonce_data.span());
            let expires_at = timestamp + CHALLENGE_EXPIRY_SECS;

            agent.active_nonce     = nonce;
            agent.nonce_expiry     = expires_at;
            agent.nonce_amount     = amount;
            agent.nonce_merchant   = merchant;
            agent.nonce_conf_score = behavioral_score;
            agent.challenge_active = true;
            agent.total_challenges_issued += 1;
            self.agents.entry(agent_id).write(agent);
            self.emit(ChallengeIssued { agent_id, nonce, expires_at });

            self.reentrancy_guard.end();
            AuthResult {
                approved:        false,
                conf_score:      behavioral_score,
                spending_limit:  0,
                flag_owner:      false,
                needs_challenge: true,
                challenge:       ChallengeIssuance { nonce, expires_at },
                reason:          'CHALLENGE_REQUIRED',
            }
        }

        fn submit_challenge_response(
            ref self: ContractState,
            agent_id:       felt252,
            nonce:          felt252,
            response_hash:  felt252,
            response_valid: bool,
        ) -> AuthResult {
            self.reentrancy_guard.start();
            self._only_relayer();

            let mut agent = self.agents.entry(agent_id).read();
            let timestamp = get_block_timestamp();
            let empty_challenge = ChallengeIssuance { nonce: 0, expires_at: 0 };

            assert(agent.challenge_active, 'BCI: no active challenge');
            assert(nonce == agent.active_nonce, 'BCI: wrong nonce');
            assert(timestamp <= agent.nonce_expiry, 'BCI: challenge expired');

            agent.challenge_active = false;
            agent.active_nonce     = 0;

            if !response_valid {
                agent.challenge_failure_count += 1;
                let failure_count = agent.challenge_failure_count;

                if failure_count >= MAX_FAILURES {
                    agent.locked_until  = timestamp + LOCKOUT_DURATION_SECS;
                    agent.is_revoked    = true;
                    agent.revoke_reason = 'REPEATED_CHALLENGE_FAILURES';
                    let owner       = agent.owner_wallet;
                    let locked_until = agent.locked_until;
                    self.agents.entry(agent_id).write(agent);
                    self.emit(AgentLockedOut { agent_id, owner, locked_until, reason: 'REPEATED_CHALLENGE_FAILURES' });
                    self.emit(SuspectedImpersonation { agent_id, owner, failure_count, timestamp });
                    self.emit(AgentRevoked { agent_id, owner, reason: 'REPEATED_CHALLENGE_FAILURES', timestamp });
                    self.reentrancy_guard.end();
                    return AuthResult { approved: false, conf_score: 0, spending_limit: 0, flag_owner: true, needs_challenge: false, challenge: empty_challenge, reason: 'REVOKED_AUTO' };
                }

                let owner = agent.owner_wallet;
                self.agents.entry(agent_id).write(agent);
                self.emit(ChallengeFailed { agent_id, owner, failure_count, timestamp });
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score: 0, spending_limit: 0, flag_owner: true, needs_challenge: false, challenge: empty_challenge, reason: 'CHALLENGE_FAILED' };
            }

            agent.challenge_failure_count  = 0;
            agent.behavioral_failure_count = 0;
            agent.total_challenges_passed += 1;

            let conf_score = agent.nonce_conf_score;
            let amount     = agent.nonce_amount;
            let merchant   = agent.nonce_merchant;

            let limit = if conf_score >= CONFIDENCE_HIGH {
                agent.high_conf_daily_limit
            } else {
                agent.med_conf_daily_limit
            };
            let flag = conf_score < CONFIDENCE_HIGH;

            let today = timestamp / DAILY_SECS;
            if today > agent.last_spend_day {
                agent.daily_spent    = 0;
                agent.last_spend_day = today;
            }

            if agent.daily_spent + amount > limit {
                self.agents.entry(agent_id).write(agent);
                self.reentrancy_guard.end();
                return AuthResult { approved: false, conf_score, spending_limit: limit, flag_owner: false, needs_challenge: false, challenge: empty_challenge, reason: 'DAILY_LIMIT_EXCEEDED' };
            }

            agent.daily_spent          += amount;
            agent.last_conf_score       = conf_score;
            agent.consecutive_low_conf  = 0;
            agent.total_transactions   += 1;
            if flag { agent.flagged_transactions += 1; }
            let owner = agent.owner_wallet;
            self.agents.entry(agent_id).write(agent);

            if flag { self.emit(AgentFlagged { agent_id, owner, conf_score, timestamp }); }
            self.emit(ChallengePassed { agent_id, amount, conf_score, timestamp });
            self.emit(TransactionAuthorized { agent_id, amount, conf_score, merchant, timestamp });

            self.reentrancy_guard.end();
            AuthResult {
                approved:        true,
                conf_score,
                spending_limit:  limit,
                flag_owner:      flag,
                needs_challenge: false,
                challenge:       empty_challenge,
                reason:          'APPROVED',
            }
        }

        fn update_template_drift(
            ref self: ContractState,
            agent_id:         felt252,
            new_template:     BCITemplate,
            drift_sigma_x100: u64,
            owner_signature:  felt252,
        ) {
            self._only_relayer();
            let agent     = self.agents.entry(agent_id).read();
            let timestamp = get_block_timestamp();

            if drift_sigma_x100 > DRIFT_ALERT_SIGMA_X100 {
                let day = timestamp / DAILY_SECS;
                let mut sig_data: Array<felt252> = ArrayTrait::new();
                sig_data.append(agent_id);
                sig_data.append(drift_sigma_x100.into());
                sig_data.append(day.into());
                let expected_sig = poseidon_hash_span(sig_data.span());
                assert(owner_signature == expected_sig, 'BCI: major drift owner sig');
                self.emit(MajorDriftDetected { agent_id, owner: agent.owner_wallet, drift_sigma_x100, timestamp });
            }

            let old = self.templates.entry(agent_id).read();
            let new_version = old.template_version + 1;
            let mut t = new_template;
            t.commitment_hash          = old.commitment_hash;
            t.binary_high              = old.binary_high;
            t.binary_low               = old.binary_low;
            t.enrollment_response_seed = old.enrollment_response_seed;
            t.ms_commitment            = old.ms_commitment;
            t.ms_receipt_verifier      = old.ms_receipt_verifier;
            t.enrollment_timestamp     = old.enrollment_timestamp;
            t.template_version         = new_version;
            t.last_drift_update        = timestamp;
            t.is_active                = true;
            self.templates.entry(agent_id).write(t);

            self.emit(TemplateDriftUpdated { agent_id, drift_sigma_x100, new_version, timestamp });
        }

        fn verify_global_identity(
            self:             @ContractState,
            agent_id:         felt252,
            behavioral_score: u64,
            response_valid:   bool,
        ) -> bool {
            let agent = self.agents.entry(agent_id).read();
            if !agent.enrollment_complete || agent.is_revoked { return false; }
            if get_block_timestamp() < agent.locked_until { return false; }
            if behavioral_score < CONFIDENCE_MED { return false; }
            response_valid
        }

        fn rotate_auth_key(
            ref self: ContractState,
            agent_id:     felt252,
            new_key_hash: felt252,
            new_expiry:   u64,
        ) {
            self._only_agent_owner(agent_id);
            let mut agent = self.agents.entry(agent_id).read();
            assert(!agent.is_revoked, 'BCI: revoked');
            agent.current_auth_key_hash   = new_key_hash;
            agent.auth_key_expiry         = new_expiry;
            agent.challenge_failure_count = 0;
            self.agents.entry(agent_id).write(agent);
            self.emit(AuthKeyRotated { agent_id, new_expiry, timestamp: get_block_timestamp() });
        }

        fn request_reenrollment(ref self: ContractState, agent_id: felt252) {
            self._only_agent_owner(agent_id);
            let mut agent = self.agents.entry(agent_id).read();
            let timestamp = get_block_timestamp();
            agent.enrollment_complete      = false;
            agent.ms_provisioned           = false;
            agent.enrollment_start         = timestamp;
            agent.enrollment_extensions    = 0;
            agent.challenge_failure_count  = 0;
            agent.behavioral_failure_count = 0;
            agent.locked_until             = 0;
            self.agents.entry(agent_id).write(agent);
            self.obs_count.entry(agent_id).write(0);
            self.obs_chain_hash.entry(agent_id).write(0);
            self.emit(ReenrollmentRequested { agent_id, owner: get_caller_address(), timestamp });
        }

        fn revoke_agent(ref self: ContractState, agent_id: felt252, reason: felt252) {
            self._only_agent_owner(agent_id);
            let mut agent = self.agents.entry(agent_id).read();
            agent.is_revoked    = true;
            agent.revoke_reason = reason;
            self.agents.entry(agent_id).write(agent);
            self.emit(AgentRevoked { agent_id, owner: get_caller_address(), reason, timestamp: get_block_timestamp() });
        }

        fn update_spending_limits(
            ref self: ContractState,
            agent_id:              felt252,
            high_conf_daily_limit: u256,
            med_conf_daily_limit:  u256,
        ) {
            self._only_agent_owner(agent_id);
            let mut agent = self.agents.entry(agent_id).read();
            agent.high_conf_daily_limit = high_conf_daily_limit;
            agent.med_conf_daily_limit  = med_conf_daily_limit;
            self.agents.entry(agent_id).write(agent);
        }

        // ── Views ─────────────────────────────────────────────

        fn get_agent(self: @ContractState, agent_id: felt252) -> AgentRegistration {
            self.agents.entry(agent_id).read()
        }
        fn get_template(self: @ContractState, agent_id: felt252) -> BCITemplate {
            self.templates.entry(agent_id).read()
        }
        fn has_global_identity(self: @ContractState, agent_id: felt252) -> bool {
            let agent = self.agents.entry(agent_id).read();
            agent.enrollment_complete && !agent.is_revoked
        }
        fn is_locked_out(self: @ContractState, agent_id: felt252) -> bool {
            let agent = self.agents.entry(agent_id).read();
            get_block_timestamp() < agent.locked_until
        }
        fn get_enrollment_response_seed(self: @ContractState, agent_id: felt252) -> felt252 {
            self.templates.entry(agent_id).read().enrollment_response_seed
        }
    }
}
