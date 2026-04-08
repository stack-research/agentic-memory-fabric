import pathlib
import sys
import unittest
from dataclasses import replace

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.policy import (
    OVERRIDE_CAPABILITY,
    PolicyContext,
    evaluate_query_gate,
)
from agentic_memory_fabric.decay import DecayPolicy
from agentic_memory_fabric.replay import LIFECYCLE_ACTIVE, LIFECYCLE_DELETED, MemoryState
from agentic_memory_fabric.retrieval import get, get_outcome, query, query_with_summary


class RetrievalPolicyTests(unittest.TestCase):
    def _state_map(self) -> dict[str, MemoryState]:
        return {
            "mem-trusted": MemoryState(
                memory_id="mem-trusted",
                tenant_id="tenant-alpha",
                version=2,
                trust_state="trusted",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="11111111-1111-4111-8111-111111111111",
                last_sequence=2,
                last_event_type="updated",
                signature_state="verified",
                last_tick=2,
                payload_hash="sha256:" + ("a" * 64),
                previous_events=("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",),
            ),
            "mem-quarantined": MemoryState(
                memory_id="mem-quarantined",
                tenant_id="tenant-alpha",
                version=3,
                trust_state="quarantined",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="22222222-2222-4222-8222-222222222222",
                last_sequence=3,
                last_event_type="quarantined",
                signature_state="verified",
                last_tick=3,
                payload_hash="sha256:" + ("b" * 64),
                previous_events=("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",),
            ),
            "mem-expired": MemoryState(
                memory_id="mem-expired",
                tenant_id="tenant-alpha",
                version=4,
                trust_state="expired",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="33333333-3333-4333-8333-333333333333",
                last_sequence=4,
                last_event_type="expired",
                signature_state="verified",
                last_tick=4,
                payload_hash="sha256:" + ("c" * 64),
                previous_events=("cccccccc-cccc-4ccc-8ccc-cccccccccccc",),
            ),
            "mem-deleted": MemoryState(
                memory_id="mem-deleted",
                tenant_id="tenant-alpha",
                version=5,
                trust_state="trusted",
                lifecycle_state=LIFECYCLE_DELETED,
                last_event_id="44444444-4444-4444-8444-444444444444",
                last_sequence=5,
                last_event_type="deleted",
                signature_state="verified",
                last_tick=5,
                payload_hash="sha256:" + ("d" * 64),
                previous_events=("dddddddd-dddd-4ddd-8ddd-dddddddddddd",),
            ),
            "mem-key-missing": MemoryState(
                memory_id="mem-key-missing",
                tenant_id="tenant-alpha",
                version=1,
                trust_state="trusted",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="55555555-5555-4555-8555-555555555555",
                last_sequence=6,
                last_event_type="updated",
                signature_state="key_missing",
                last_tick=6,
                payload_hash="sha256:" + ("e" * 64),
                previous_events=("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",),
            ),
            "mem-key-revoked": MemoryState(
                memory_id="mem-key-revoked",
                tenant_id="tenant-alpha",
                version=1,
                trust_state="trusted",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="66666666-6666-4666-8666-666666666666",
                last_sequence=7,
                last_event_type="updated",
                signature_state="revoked",
                last_tick=7,
                payload_hash="sha256:" + ("f" * 64),
                previous_events=("ffffffff-ffff-4fff-8fff-ffffffffffff",),
            ),
        }

    def test_get_allows_trusted_active_with_required_provenance_fields(self) -> None:
        state_map = self._state_map()
        record = get("mem-trusted", state_map, PolicyContext(tenant_id="tenant-alpha"))
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.trust_state, "trusted")
        self.assertEqual(record.version, 2)
        self.assertEqual(record.last_event_id, "11111111-1111-4111-8111-111111111111")
        self.assertEqual(record.why_sound, "trusted_active_under_policy")
        self.assertEqual(record.lineage_depth, 0)
        self.assertEqual(record.recall_count, 0)
        self.assertIsNone(record.last_recall_tick)

    def test_get_default_denies_quarantined_expired_and_deleted(self) -> None:
        state_map = self._state_map()
        ctx = PolicyContext(tenant_id="tenant-alpha")
        self.assertIsNone(get("mem-quarantined", state_map, ctx))
        self.assertIsNone(get("mem-expired", state_map, ctx))
        self.assertIsNone(get("mem-deleted", state_map, ctx))

    def test_query_default_returns_only_sound_memories(self) -> None:
        records = query(self._state_map(), PolicyContext(tenant_id="tenant-alpha"))
        self.assertEqual([record.memory_id for record in records], ["mem-trusted"])

    def test_override_path_includes_denied_states_with_reason(self) -> None:
        state_map = self._state_map()
        override_ctx = PolicyContext(
            capabilities=frozenset({OVERRIDE_CAPABILITY}),
            tenant_id="tenant-alpha",
            trusted_subject=True,
        )

        records = query(state_map, override_ctx)
        by_id = {record.memory_id: record for record in records}
        self.assertIn("mem-quarantined", by_id)
        self.assertIn("mem-expired", by_id)
        self.assertIn("mem-deleted", by_id)

        quarantined = by_id["mem-quarantined"]
        self.assertTrue(quarantined.override_used)
        self.assertEqual(quarantined.denial_reason, "quarantined_memory_default_deny")
        self.assertEqual(quarantined.why_sound, "override:quarantined_memory_default_deny")

    def test_query_honors_trust_state_filter_and_limit(self) -> None:
        state_map = self._state_map()
        records = query(
            state_map,
            PolicyContext(
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                tenant_id="tenant-alpha",
                trusted_subject=True,
            ),
            trust_states={"expired", "quarantined"},
            limit=1,
        )
        self.assertEqual(len(records), 1)
        self.assertIn(records[0].trust_state, {"expired", "quarantined"})

    def test_decay_denies_when_age_exceeds_threshold(self) -> None:
        state_map = self._state_map()
        ctx = PolicyContext(
            tenant_id="tenant-alpha",
            current_tick=20,
            decay_policy=DecayPolicy(max_age_ticks=5),
        )
        self.assertIsNone(get("mem-trusted", state_map, ctx))

    def test_query_denies_cross_tenant_without_override(self) -> None:
        records = query(self._state_map(), PolicyContext(tenant_id="tenant-bravo"))
        self.assertEqual(records, [])

    def test_key_lifecycle_denials_are_deterministic(self) -> None:
        records = query(
            self._state_map(),
            PolicyContext(
                tenant_id="tenant-alpha",
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                trusted_subject=True,
            ),
        )
        by_id = {record.memory_id: record for record in records}
        self.assertEqual(by_id["mem-key-missing"].denial_reason, "signature_key_missing_default_deny")
        self.assertEqual(by_id["mem-key-revoked"].denial_reason, "signature_key_revoked_default_deny")

    def test_decay_precedence_over_signature_denial(self) -> None:
        stale_invalid = MemoryState(
            memory_id="mem-stale-invalid",
            tenant_id="tenant-alpha",
            version=1,
            trust_state="trusted",
            lifecycle_state=LIFECYCLE_ACTIVE,
            last_event_id="77777777-7777-4777-8777-777777777777",
            last_sequence=8,
            last_event_type="updated",
            signature_state="invalid",
            last_tick=1,
            payload_hash="sha256:" + ("1" * 64),
            previous_events=(),
        )
        records = query(
            {"mem-stale-invalid": stale_invalid},
            PolicyContext(
                tenant_id="tenant-alpha",
                current_tick=20,
                decay_policy=DecayPolicy(max_age_ticks=3),
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                trusted_subject=True,
            ),
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].denial_reason, "decay_expired_default_deny")

    def test_query_with_summary_matches_query_and_denial_histogram(self) -> None:
        state_map = self._state_map()
        ctx = PolicyContext(tenant_id="tenant-alpha")
        records = query(state_map, ctx)
        records_with_summary, summary = query_with_summary(state_map, ctx)
        self.assertEqual([record.memory_id for record in records_with_summary], [record.memory_id for record in records])
        self.assertEqual(summary.allowed, len(records))
        self.assertEqual(summary.considered, len(state_map))
        self.assertEqual(summary.denied_by_reason["quarantined_memory_default_deny"], 1)
        self.assertEqual(summary.denied_by_reason["expired_memory_default_deny"], 1)
        self.assertEqual(summary.denied_by_reason["deleted_memory_default_deny"], 1)
        self.assertEqual(summary.denied_by_reason["signature_key_missing_default_deny"], 1)
        self.assertEqual(summary.denied_by_reason["signature_key_revoked_default_deny"], 1)

    def test_get_outcome_distinguishes_not_found_denied_and_allowed(self) -> None:
        state_map = self._state_map()
        allowed = get_outcome("mem-trusted", state_map, PolicyContext(tenant_id="tenant-alpha"))
        denied = get_outcome("mem-quarantined", state_map, PolicyContext(tenant_id="tenant-alpha"))
        missing = get_outcome("mem-missing", state_map, PolicyContext(tenant_id="tenant-alpha"))
        self.assertEqual(allowed.outcome, "allowed")
        self.assertIsNotNone(allowed.record)
        self.assertEqual(denied.outcome, "denied")
        self.assertEqual(denied.denial_reason, "quarantined_memory_default_deny")
        self.assertEqual(missing.outcome, "not_found")

    def test_attestation_policy_is_opt_in_by_default(self) -> None:
        records = query(self._state_map(), PolicyContext(tenant_id="tenant-alpha"))
        self.assertEqual([record.memory_id for record in records], ["mem-trusted"])

    def test_query_gate_allows_when_threshold_not_configured(self) -> None:
        decision = evaluate_query_gate(PolicyContext(tenant_id="tenant-alpha"))
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.denial_reason)

    def test_query_gate_denies_missing_signal_when_threshold_is_set(self) -> None:
        decision = evaluate_query_gate(
            PolicyContext(tenant_id="tenant-alpha", uncertainty_threshold=0.8)
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.denial_reason, "uncertainty_signal_required_default_deny")

    def test_query_gate_denies_below_threshold_and_allows_override(self) -> None:
        denied = evaluate_query_gate(
            PolicyContext(
                tenant_id="tenant-alpha",
                uncertainty_score=0.4,
                uncertainty_threshold=0.8,
            )
        )
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.denial_reason, "uncertainty_below_threshold_default_deny")

        override = evaluate_query_gate(
            PolicyContext(
                tenant_id="tenant-alpha",
                uncertainty_score=0.4,
                uncertainty_threshold=0.8,
                allow_low_uncertainty_override=True,
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                trusted_subject=True,
            )
        )
        self.assertTrue(override.allowed)
        self.assertEqual(override.denial_reason, "uncertainty_below_threshold_default_deny")
        self.assertTrue(override.override_used)

    def test_require_attestation_denies_unattested(self) -> None:
        records = query(
            self._state_map(),
            PolicyContext(tenant_id="tenant-alpha", require_attestation=True),
        )
        self.assertEqual(records, [])

    def test_min_attestation_trust_level_filters_low_attestation(self) -> None:
        state_map = self._state_map()
        state_map["mem-trusted"] = replace(
            state_map["mem-trusted"],
            has_attestation=True,
            attestation_trust_level="low",
            attestation_issuer="issuer-a",
        )
        state_map["mem-attested-high"] = MemoryState(
            memory_id="mem-attested-high",
            tenant_id="tenant-alpha",
            version=1,
            trust_state="trusted",
            lifecycle_state=LIFECYCLE_ACTIVE,
            last_event_id="88888888-8888-4888-8888-888888888888",
            last_sequence=9,
            last_event_type="attested",
            signature_state="verified",
            last_tick=9,
            payload_hash="sha256:" + ("8" * 64),
            previous_events=(),
            has_attestation=True,
            attestation_trust_level="high",
            attestation_issuer="issuer-b",
        )
        records = query(
            state_map,
            PolicyContext(tenant_id="tenant-alpha", min_attestation_trust_level="medium"),
        )
        self.assertEqual([record.memory_id for record in records], ["mem-attested-high"])

    def test_allowed_attestation_issuers_gate(self) -> None:
        state_map = self._state_map()
        state_map["mem-trusted"] = replace(
            state_map["mem-trusted"],
            has_attestation=True,
            attestation_trust_level="high",
            attestation_issuer="issuer-a",
        )
        records = query(
            state_map,
            PolicyContext(
                tenant_id="tenant-alpha",
                allowed_attestation_issuers=frozenset({"issuer-b"}),
            ),
        )
        self.assertEqual(records, [])

    def test_override_keeps_attestation_denial_reason(self) -> None:
        records = query(
            self._state_map(),
            PolicyContext(
                tenant_id="tenant-alpha",
                require_attestation=True,
                capabilities=frozenset({OVERRIDE_CAPABILITY}),
                trusted_subject=True,
            ),
        )
        by_id = {record.memory_id: record for record in records}
        self.assertIn("mem-trusted", by_id)
        self.assertEqual(by_id["mem-trusted"].denial_reason, "attestation_required_default_deny")
