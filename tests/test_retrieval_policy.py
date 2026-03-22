import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_memory_fabric.policy import OVERRIDE_CAPABILITY, PolicyContext
from agentic_memory_fabric.decay import DecayPolicy
from agentic_memory_fabric.replay import LIFECYCLE_ACTIVE, LIFECYCLE_DELETED, MemoryState
from agentic_memory_fabric.retrieval import get, query


class RetrievalPolicyTests(unittest.TestCase):
    def _state_map(self) -> dict[str, MemoryState]:
        return {
            "mem-trusted": MemoryState(
                memory_id="mem-trusted",
                version=2,
                trust_state="trusted",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="11111111-1111-4111-8111-111111111111",
                last_sequence=2,
                last_event_type="updated",
                last_tick=2,
                payload_hash="sha256:" + ("a" * 64),
                previous_events=("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",),
            ),
            "mem-quarantined": MemoryState(
                memory_id="mem-quarantined",
                version=3,
                trust_state="quarantined",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="22222222-2222-4222-8222-222222222222",
                last_sequence=3,
                last_event_type="quarantined",
                last_tick=3,
                payload_hash="sha256:" + ("b" * 64),
                previous_events=("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",),
            ),
            "mem-expired": MemoryState(
                memory_id="mem-expired",
                version=4,
                trust_state="expired",
                lifecycle_state=LIFECYCLE_ACTIVE,
                last_event_id="33333333-3333-4333-8333-333333333333",
                last_sequence=4,
                last_event_type="expired",
                last_tick=4,
                payload_hash="sha256:" + ("c" * 64),
                previous_events=("cccccccc-cccc-4ccc-8ccc-cccccccccccc",),
            ),
            "mem-deleted": MemoryState(
                memory_id="mem-deleted",
                version=5,
                trust_state="trusted",
                lifecycle_state=LIFECYCLE_DELETED,
                last_event_id="44444444-4444-4444-8444-444444444444",
                last_sequence=5,
                last_event_type="deleted",
                last_tick=5,
                payload_hash="sha256:" + ("d" * 64),
                previous_events=("dddddddd-dddd-4ddd-8ddd-dddddddddddd",),
            ),
        }

    def test_get_allows_trusted_active_with_required_provenance_fields(self) -> None:
        state_map = self._state_map()
        record = get("mem-trusted", state_map, PolicyContext())
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.trust_state, "trusted")
        self.assertEqual(record.version, 2)
        self.assertEqual(record.last_event_id, "11111111-1111-4111-8111-111111111111")
        self.assertEqual(record.why_sound, "trusted_active_under_policy")

    def test_get_default_denies_quarantined_expired_and_deleted(self) -> None:
        state_map = self._state_map()
        ctx = PolicyContext()
        self.assertIsNone(get("mem-quarantined", state_map, ctx))
        self.assertIsNone(get("mem-expired", state_map, ctx))
        self.assertIsNone(get("mem-deleted", state_map, ctx))

    def test_query_default_returns_only_sound_memories(self) -> None:
        records = query(self._state_map(), PolicyContext())
        self.assertEqual([record.memory_id for record in records], ["mem-trusted"])

    def test_override_path_includes_denied_states_with_reason(self) -> None:
        state_map = self._state_map()
        override_ctx = PolicyContext(capabilities=frozenset({OVERRIDE_CAPABILITY}))

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
            PolicyContext(capabilities=frozenset({OVERRIDE_CAPABILITY})),
            trust_states={"expired", "quarantined"},
            limit=1,
        )
        self.assertEqual(len(records), 1)
        self.assertIn(records[0].trust_state, {"expired", "quarantined"})

    def test_decay_denies_when_age_exceeds_threshold(self) -> None:
        state_map = self._state_map()
        ctx = PolicyContext(current_tick=20, decay_policy=DecayPolicy(max_age_ticks=5))
        self.assertIsNone(get("mem-trusted", state_map, ctx))
