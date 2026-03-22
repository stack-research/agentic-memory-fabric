import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.decay import DecayPolicy, compute_age_ticks, evaluate_freshness
from agentic_memory_fabric.policy import OVERRIDE_CAPABILITY, PolicyContext
from agentic_memory_fabric.replay import LIFECYCLE_ACTIVE, MemoryState
from agentic_memory_fabric.retrieval import get


class DecayPolicyTests(unittest.TestCase):
    def _trusted_state(self, last_tick: int) -> MemoryState:
        return MemoryState(
            memory_id="mem-trusted",
            tenant_id="tenant-alpha",
            version=1,
            trust_state="trusted",
            lifecycle_state=LIFECYCLE_ACTIVE,
            last_event_id="11111111-1111-4111-8111-111111111111",
            last_sequence=1,
            last_event_type="created",
            signature_state="verified",
            last_tick=last_tick,
            payload_hash="sha256:" + ("a" * 64),
            previous_events=(),
        )

    def test_compute_age_ticks_from_logical_clock(self) -> None:
        self.assertEqual(compute_age_ticks(current_tick=10, last_tick=3), 7)

    def test_compute_age_ticks_rejects_backwards_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "current_tick must be >= last_tick"):
            compute_age_ticks(current_tick=2, last_tick=3)

    def test_freshness_allows_within_ttl(self) -> None:
        decision = evaluate_freshness(
            policy=DecayPolicy(max_age_ticks=5),
            current_tick=10,
            last_tick=7,
        )
        self.assertTrue(decision.is_fresh)
        self.assertEqual(decision.reason, "fresh_under_decay_policy")

    def test_freshness_expires_beyond_ttl(self) -> None:
        decision = evaluate_freshness(
            policy=DecayPolicy(max_age_ticks=2),
            current_tick=10,
            last_tick=7,
        )
        self.assertFalse(decision.is_fresh)
        self.assertEqual(decision.reason, "expired_by_decay")

    def test_retrieval_denies_decay_expired_by_default(self) -> None:
        state_map = {"mem-trusted": self._trusted_state(last_tick=3)}
        ctx = PolicyContext(
            tenant_id="tenant-alpha",
            current_tick=10,
            decay_policy=DecayPolicy(max_age_ticks=3),
        )
        self.assertIsNone(get("mem-trusted", state_map, ctx))

    def test_override_allows_decay_expired_with_reason(self) -> None:
        state_map = {"mem-trusted": self._trusted_state(last_tick=3)}
        ctx = PolicyContext(
            current_tick=10,
            decay_policy=DecayPolicy(max_age_ticks=3),
            capabilities=frozenset({OVERRIDE_CAPABILITY}),
            tenant_id="tenant-alpha",
            trusted_subject=True,
        )
        record = get("mem-trusted", state_map, ctx)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertTrue(record.override_used)
        self.assertEqual(record.denial_reason, "decay_expired_default_deny")
        self.assertEqual(record.why_sound, "override:decay_expired_default_deny")
