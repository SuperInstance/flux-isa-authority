"""
FLUX ISA Authority Arbiter — v1.0
===================================

ISA Governance Layer for resolving opcode conflicts between VM implementations.

The Critical Problem (Session 7 Finding):
  When Python VM (flux-runtime) and Go VM (greenhorn-runtime) assign different
  opcode numbers to the same instruction, compiled bytecode becomes unrunnable
  across implementations. This is a FATAL divergence — not a compatibility issue,
  but a correctness violation.

Solution Architecture:
  1. Opcode Registry — Single source of truth for canonical opcode mappings
  2. Conflict Detector — Automated divergence detection across implementations
  3. Arbitration Engine — Evidence-based conflict resolution with weighted voting
  4. Version Negotiator — Runtime ISA version capability exchange between agents
  5. Canonical Store — Immutable record of authority decisions with git-backed storage
  6. Migration Planner — Automated migration when opcodes change between versions

Author: Quill (Architect-rank, SuperInstance fleet)
Session: 7b — R&D Round 14
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, List, Dict, Set, Tuple, Any


# ─── Core Types ───────────────────────────────────────────────────────────────

class ConflictSeverity(IntEnum):
    """Severity of an opcode conflict."""
    INFO = 0        # Minor difference (e.g., operand encoding)
    WARNING = 1     # Format difference (e.g., imm8 vs imm16)
    ERROR = 2       # Opcode number mismatch for same mnemonic
    CRITICAL = 3    # Same opcode number maps to different mnemonics (FATAL)


class ResolutionStrategy(IntEnum):
    """Strategies for resolving opcode conflicts."""
    CONVERGED = 0    # All implementations agree — no conflict
    OLDEST_WINS = 1  # Implementation with earliest registration wins
    VOTING = 2       # Weighted vote among registered implementations
    SPEC_AUTHORITY = 3  # SIGNAL.md spec is authoritative
    LARGEST_IMPL = 4  # Implementation with most opcodes wins
    MANUAL = 5        # Requires human/fleet arbitration


@dataclass(frozen=True)
class OpcodeEntry:
    """A single opcode definition from an implementation."""
    opcode: int
    mnemonic: str
    format: str          # A, B, C, D, E, F, G
    category: str        # arithmetic, memory, a2a, etc.
    description: str = ""
    source_impl: str = ""  # Which VM implementation
    registered_at: float = 0.0

    def key(self) -> Tuple[int, str]:
        return (self.opcode, self.mnemonic)


@dataclass
class ConflictRecord:
    """Record of an opcode conflict between implementations."""
    conflict_id: str = ""
    severity: ConflictSeverity = ConflictSeverity.INFO
    description: str = ""
    entries: List[OpcodeEntry] = field(default_factory=list)
    detected_at: float = 0.0
    resolved: bool = False
    resolution: Optional[Resolution] = None

    def __post_init__(self):
        if not self.conflict_id:
            self.conflict_id = hashlib.sha256(
                f"{self.description}:{self.detected_at}".encode()
            ).hexdigest()[:12]


@dataclass
class Resolution:
    """Resolution of an opcode conflict."""
    strategy: ResolutionStrategy
    canonical_opcode: int
    canonical_mnemonic: str
    canonical_format: str
    canonical_category: str
    winning_implementation: str
    voters: Dict[str, int] = field(default_factory=dict)  # impl -> preferred opcode
    rationale: str = ""
    resolved_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "strategy": ResolutionStrategy(self.strategy).name,
            "canonical_opcode": f"0x{self.canonical_opcode:02X}",
            "canonical_mnemonic": self.canonical_mnemonic,
            "canonical_format": self.canonical_format,
            "winning_implementation": self.winning_implementation,
            "voters": self.voters,
            "rationale": self.rationale,
        }


@dataclass
class ISAVersion:
    """A versioned snapshot of the ISA."""
    version: str
    description: str
    opcode_count: int
    created_at: float = 0.0
    entries: Dict[int, OpcodeEntry] = field(default_factory=dict)
    sha256: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of all opcode entries."""
        data = json.dumps(
            {f"0x{k:02X}": (v.mnemonic, v.format) for k, v in sorted(self.entries.items())},
            sort_keys=True
        )
        self.sha256 = hashlib.sha256(data.encode()).hexdigest()
        return self.sha256


# ─── 1. Opcode Registry ─────────────────────────────────────────────────────

class OpcodeRegistry:
    """
    Central registry for opcode definitions from all implementations.

    Each implementation registers its complete opcode table. The registry
    maintains separate per-implementation tables and a merged canonical view.
    """

    def __init__(self) -> None:
        self._implementations: Dict[str, Dict[int, OpcodeEntry]] = {}
        self._registration_order: List[str] = []
        self._canonical: Dict[int, OpcodeEntry] = {}

    def register_implementation(
        self, impl_name: str, opcodes: List[OpcodeEntry]
    ) -> int:
        """
        Register a complete implementation's opcode table.

        Returns the number of opcodes registered.
        """
        table: Dict[int, OpcodeEntry] = {}
        now = time.time()
        for op in opcodes:
            entry = OpcodeEntry(
                opcode=op.opcode,
                mnemonic=op.mnemonic,
                format=op.format,
                category=op.category,
                description=op.description,
                source_impl=impl_name,
                registered_at=now,
            )
            table[op.opcode] = entry
        self._implementations[impl_name] = table
        if impl_name not in self._registration_order:
            self._registration_order.append(impl_name)
        return len(table)

    def get_implementation(self, name: str) -> Optional[Dict[int, OpcodeEntry]]:
        """Get the full opcode table for an implementation."""
        return self._implementations.get(name)

    def list_implementations(self) -> List[str]:
        """List all registered implementations in registration order."""
        return list(self._registration_order)

    def get_canonical(self) -> Dict[int, OpcodeEntry]:
        """Get the current canonical opcode mapping."""
        return dict(self._canonical)

    def set_canonical(self, opcodes: Dict[int, OpcodeEntry]) -> None:
        """Set the canonical opcode mapping (authority decision)."""
        self._canonical = dict(opcodes)

    def get_by_opcode(self, opcode: int) -> Dict[str, Optional[OpcodeEntry]]:
        """Get all implementations' definitions for a given opcode number."""
        result = {}
        for impl_name, table in self._implementations.items():
            result[impl_name] = table.get(opcode)
        return result

    def get_by_mnemonic(self, mnemonic: str) -> Dict[str, Optional[OpcodeEntry]]:
        """Get all implementations' definitions for a given mnemonic."""
        result = {}
        for impl_name, table in self._implementations.items():
            for entry in table.values():
                if entry.mnemonic == mnemonic:
                    result[impl_name] = entry
                    break
            else:
                result[impl_name] = None
        return result

    def get_opcode_range(self, impl_name: str) -> Tuple[int, int]:
        """Get the min/max opcode numbers for an implementation."""
        table = self._implementations.get(impl_name, {})
        if not table:
            return (0, 0)
        return (min(table.keys()), max(table.keys()))

    def impl_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all registered implementations."""
        stats = {}
        for name, table in self._implementations.items():
            categories = {}
            formats = {}
            for entry in table.values():
                categories[entry.category] = categories.get(entry.category, 0) + 1
                formats[entry.format] = formats.get(entry.format, 0) + 1
            stats[name] = {
                "opcode_count": len(table),
                "categories": categories,
                "formats": formats,
                "range": self.get_opcode_range(name),
            }
        return stats


# ─── 2. Conflict Detector ────────────────────────────────────────────────────

class ConflictDetector:
    """
    Automated detection of opcode conflicts between implementations.

    Detects three types of conflicts:
    1. Number Collision: Same opcode → different mnemonics (CRITICAL)
    2. Mnemonic Divergence: Same mnemonic → different opcodes (ERROR)
    3. Format Mismatch: Same mnemonic+opcode → different format (WARNING)
    """

    def __init__(self, registry: OpcodeRegistry) -> None:
        self.registry = registry

    def find_all_conflicts(self) -> List[ConflictRecord]:
        """Find all conflicts across all registered implementations."""
        conflicts: List[ConflictRecord] = []
        impls = self.registry.list_implementations()

        if len(impls) < 2:
            return conflicts

        # Type 1: Number collision — same opcode, different mnemonic
        conflicts.extend(self._find_number_collisions(impls))

        # Type 2: Mnemonic divergence — same mnemonic, different opcode
        conflicts.extend(self._find_mnemonic_divergences(impls))

        # Type 3: Format mismatch — same mnemonic+opcode, different format
        conflicts.extend(self._find_format_mismatches(impls))

        return conflicts

    def _find_number_collisions(self, impls: List[str]) -> List[ConflictRecord]:
        """Find opcodes where different implementations have different mnemonics."""
        conflicts = []
        now = time.time()

        # Collect all opcodes across all implementations
        all_opcodes: Set[int] = set()
        for impl in impls:
            table = self.registry.get_implementation(impl)
            if table:
                all_opcodes.update(table.keys())

        for opcode in sorted(all_opcodes):
            by_impl = self.registry.get_by_opcode(opcode)
            mnemonics = {impl: entry.mnemonic for impl, entry in by_impl.items() if entry}

            if len(set(mnemonics.values())) > 1:
                # Different mnemonics for same opcode number — FATAL
                entries = [entry for entry in by_impl.values() if entry]
                conflicts.append(ConflictRecord(
                    severity=ConflictSeverity.CRITICAL,
                    description=(
                        f"Opcode 0x{opcode:02X} maps to different instructions: "
                        + ", ".join(f"{m} ({i})" for i, m in mnemonics.items())
                    ),
                    entries=entries,
                    detected_at=now,
                ))

        return conflicts

    def _find_mnemonic_divergences(self, impls: List[str]) -> List[ConflictRecord]:
        """Find mnemonics where different implementations use different opcode numbers."""
        conflicts = []
        now = time.time()

        # Collect all mnemonics
        all_mnemonics: Set[str] = set()
        for impl in impls:
            table = self.registry.get_implementation(impl)
            if table:
                for entry in table.values():
                    all_mnemonics.add(entry.mnemonic)

        for mnemonic in sorted(all_mnemonics):
            by_impl = self.registry.get_by_mnemonic(mnemonic)
            opcodes = {impl: entry.opcode for impl, entry in by_impl.items() if entry}

            if len(set(opcodes.values())) > 1:
                entries = [entry for entry in by_impl.values() if entry]
                conflicts.append(ConflictRecord(
                    severity=ConflictSeverity.ERROR,
                    description=(
                        f"Mnemonic {mnemonic} has different opcode numbers: "
                        + ", ".join(f"0x{o:02X} ({i})" for i, o in opcodes.items())
                    ),
                    entries=entries,
                    detected_at=now,
                ))

        return conflicts

    def _find_format_mismatches(self, impls: List[str]) -> List[ConflictRecord]:
        """Find opcodes where the same mnemonic has different encoding formats."""
        conflicts = []
        now = time.time()

        all_mnemonics: Set[str] = set()
        for impl in impls:
            table = self.registry.get_implementation(impl)
            if table:
                for entry in table.values():
                    all_mnemonics.add(entry.mnemonic)

        for mnemonic in sorted(all_mnemonics):
            by_impl = self.registry.get_by_mnemonic(mnemonic)
            formats = {impl: entry.format for impl, entry in by_impl.items() if entry}

            if len(set(formats.values())) > 1:
                entries = [entry for entry in by_impl.values() if entry]
                conflicts.append(ConflictRecord(
                    severity=ConflictSeverity.WARNING,
                    description=(
                        f"Mnemonic {mnemonic} has different formats: "
                        + ", ".join(f"{f} ({i})" for i, f in formats.items())
                    ),
                    entries=entries,
                    detected_at=now,
                ))

        return conflicts

    def summary(self, conflicts: List[ConflictRecord]) -> str:
        """Generate a human-readable conflict summary."""
        by_severity = {s: 0 for s in ConflictSeverity}
        for c in conflicts:
            by_severity[c.severity] += 1

        lines = [
            "ISA Conflict Detection Report",
            f"  Implementations scanned: {len(self.registry.list_implementations())}",
            f"  Total conflicts: {len(conflicts)}",
            f"    CRITICAL (same opcode, different mnemonic): {by_severity[ConflictSeverity.CRITICAL]}",
            f"    ERROR (same mnemonic, different opcode): {by_severity[ConflictSeverity.ERROR]}",
            f"    WARNING (format mismatch): {by_severity[ConflictSeverity.WARNING]}",
        ]

        for c in conflicts:
            sev = ConflictSeverity(c.severity).name
            lines.append(f"  [{sev}] {c.description}")

        return "\n".join(lines)


# ─── 3. Arbitration Engine ───────────────────────────────────────────────────

class ArbitrationEngine:
    """
    Evidence-based conflict resolution with weighted voting.

    Resolution strategies:
    - CONVERGED: No conflict (all implementations agree)
    - OLDEST_WINS: First-registered implementation determines canonical mapping
    - VOTING: Each implementation votes for its own mapping; majority wins
    - SPEC_AUTHORITY: SIGNAL.md spec document is authoritative
    - LARGEST_IMPL: Implementation with most opcodes has authority
    - MANUAL: Requires fleet/Oracle1 intervention
    """

    def __init__(
        self,
        registry: OpcodeRegistry,
        strategy: ResolutionStrategy = ResolutionStrategy.VOTING,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        self.registry = registry
        self.strategy = strategy
        self.weights = weights or {}

    def arbitrate(self, conflict: ConflictRecord) -> Resolution:
        """Resolve a single conflict using the configured strategy."""
        if not conflict.entries:
            return Resolution(
                strategy=ResolutionStrategy.MANUAL,
                canonical_opcode=0, canonical_mnemonic="",
                canonical_format="", canonical_category="",
                winning_implementation="none",
                rationale="No entries to arbitrate",
                resolved_at=time.time(),
            )

        if self.strategy == ResolutionStrategy.OLDEST_WINS:
            return self._resolve_oldest_wins(conflict)
        elif self.strategy == ResolutionStrategy.VOTING:
            return self._resolve_voting(conflict)
        elif self.strategy == ResolutionStrategy.LARGEST_IMPL:
            return self._resolve_largest(conflict)
        else:
            return self._resolve_oldest_wins(conflict)

    def arbitrate_all(
        self, conflicts: List[ConflictRecord]
    ) -> Tuple[List[Resolution], List[ConflictRecord]]:
        """Resolve all conflicts. Returns (resolutions, unresolved)."""
        resolutions = []
        unresolved = []
        for conflict in conflicts:
            try:
                res = self.arbitrate(conflict)
                conflict.resolved = True
                conflict.resolution = res
                resolutions.append(res)
            except Exception:
                unresolved.append(conflict)
        return resolutions, unresolved

    def _resolve_oldest_wins(self, conflict: ConflictRecord) -> Resolution:
        """First-registered implementation wins."""
        impl_order = self.registry.list_implementations()
        for impl in impl_order:
            for entry in conflict.entries:
                if entry.source_impl == impl:
                    return Resolution(
                        strategy=ResolutionStrategy.OLDEST_WINS,
                        canonical_opcode=entry.opcode,
                        canonical_mnemonic=entry.mnemonic,
                        canonical_format=entry.format,
                        canonical_category=entry.category,
                        winning_implementation=impl,
                        voters={e.source_impl: e.opcode for e in conflict.entries},
                        rationale=f"{impl} was registered first and determines canonical mapping",
                        resolved_at=time.time(),
                    )
        # Fallback
        entry = conflict.entries[0]
        return Resolution(
            strategy=ResolutionStrategy.OLDEST_WINS,
            canonical_opcode=entry.opcode,
            canonical_mnemonic=entry.mnemonic,
            canonical_format=entry.format,
            canonical_category=entry.category,
            winning_implementation=entry.source_impl,
            voters={e.source_impl: e.opcode for e in conflict.entries},
            rationale="Fallback: first entry used",
            resolved_at=time.time(),
        )

    def _resolve_voting(self, conflict: ConflictRecord) -> Resolution:
        """Weighted voting among implementations."""
        # Count votes by opcode number
        votes: Dict[int, int] = {}
        vote_details: Dict[str, int] = {}
        for entry in conflict.entries:
            weight = self.weights.get(entry.source_impl, 1.0)
            votes[entry.opcode] = votes.get(entry.opcode, 0) + weight
            vote_details[entry.source_impl] = entry.opcode

        # Find winner
        winner_opcode = max(votes, key=votes.get)
        winner_entry = next(e for e in conflict.entries if e.opcode == winner_opcode)

        return Resolution(
            strategy=ResolutionStrategy.VOTING,
            canonical_opcode=winner_opcode,
            canonical_mnemonic=winner_entry.mnemonic,
            canonical_format=winner_entry.format,
            canonical_category=winner_entry.category,
            winning_implementation=winner_entry.source_impl,
            voters=vote_details,
            rationale=(
                f"Voting result: opcode 0x{winner_opcode:02X} received "
                f"{votes[winner_opcode]} weighted votes"
            ),
            resolved_at=time.time(),
        )

    def _resolve_largest(self, conflict: ConflictRecord) -> Resolution:
        """Implementation with most opcodes wins."""
        impl_sizes = {}
        for entry in conflict.entries:
            table = self.registry.get_implementation(entry.source_impl)
            impl_sizes[entry.source_impl] = len(table) if table else 0

        largest_impl = max(impl_sizes, key=impl_sizes.get)
        winner_entry = next(e for e in conflict.entries if e.source_impl == largest_impl)

        return Resolution(
            strategy=ResolutionStrategy.LARGEST_IMPL,
            canonical_opcode=winner_entry.opcode,
            canonical_mnemonic=winner_entry.mnemonic,
            canonical_format=winner_entry.format,
            canonical_category=winner_entry.category,
            winning_implementation=largest_impl,
            voters={e.source_impl: e.opcode for e in conflict.entries},
            rationale=(
                f"{largest_impl} has the largest ISA ({impl_sizes[largest_impl]} opcodes) "
                f"and determines canonical mapping"
            ),
            resolved_at=time.time(),
        )


# ─── 4. Version Negotiator ──────────────────────────────────────────────────

@dataclass
class CapabilityAdvertisement:
    """An implementation advertising its ISA capabilities."""
    impl_name: str
    isa_version: str
    opcode_count: int
    supported_formats: Set[str]
    supported_categories: Set[str]
    max_register: int = 31
    features: List[str] = field(default_factory=list)

    def compatible_with(self, other: CapabilityAdvertisement) -> bool:
        """Check basic compatibility with another implementation."""
        if self.supported_formats != other.supported_formats:
            return False
        if not self.supported_categories.issuperset(other.supported_categories) and \
           not other.supported_categories.issuperset(self.supported_categories):
            # Partial overlap — not fully compatible
            pass
        return True

    def compatibility_score(self, other: CapabilityAdvertisement) -> float:
        """Compute compatibility score (0.0 to 1.0)."""
        format_overlap = len(self.supported_formats & other.supported_formats)
        format_total = len(self.supported_formats | other.supported_formats)
        category_overlap = len(self.supported_categories & other.supported_categories)
        category_total = len(self.supported_categories | other.supported_categories)

        if format_total == 0 or category_total == 0:
            return 0.0

        return (format_overlap / format_total + category_overlap / category_total) / 2


class VersionNegotiator:
    """
    Runtime ISA version negotiation between implementations.

    When two agents need to exchange bytecode, they negotiate a common ISA
    version that both support. This is analogous to TLS version negotiation.
    """

    def __init__(self) -> None:
        self._advertisements: Dict[str, CapabilityAdvertisement] = {}

    def advertise(self, caps: CapabilityAdvertisement) -> None:
        """Register an implementation's capabilities."""
        self._advertisements[caps.impl_name] = caps

    def get_advertisement(self, impl_name: str) -> Optional[CapabilityAdvertisement]:
        """Get an implementation's capability advertisement."""
        return self._advertisements.get(impl_name)

    def negotiate(
        self, impl_a: str, impl_b: str
    ) -> Optional[Dict[str, Any]]:
        """
        Negotiate a common ISA version between two implementations.

        Returns a negotiation result with the agreed version and
        any limitations, or None if negotiation fails.
        """
        caps_a = self._advertisements.get(impl_a)
        caps_b = self._advertisements.get(impl_b)

        if not caps_a or not caps_b:
            return None

        score = caps_a.compatibility_score(caps_b)
        if score < 0.5:
            return None  # Too incompatible

        # Determine common subset
        common_formats = caps_a.supported_formats & caps_b.supported_formats
        common_categories = caps_a.supported_categories & caps_b.supported_categories

        return {
            "compatible": True,
            "score": round(score, 3),
            "common_formats": sorted(common_formats),
            "common_categories": sorted(common_categories),
            "suggested_version": min(caps_a.isa_version, caps_b.isa_version),
            "limitations": self._detect_limitations(caps_a, caps_b),
        }

    def _detect_limitations(
        self, a: CapabilityAdvertisement, b: CapabilityAdvertisement
    ) -> List[str]:
        """Detect what capabilities are lost when using the common subset."""
        limitations = []
        a_only = a.supported_categories - b.supported_categories
        b_only = b.supported_categories - a.supported_categories
        if a_only:
            limitations.append(f"{a.impl_name}-only categories: {sorted(a_only)}")
        if b_only:
            limitations.append(f"{b.impl_name}-only categories: {sorted(b_only)}")
        return limitations

    def fleet_compatibility_matrix(self) -> Dict[str, Dict[str, float]]:
        """Build a pairwise compatibility matrix for all implementations."""
        impls = list(self._advertisements.keys())
        matrix: Dict[str, Dict[str, float]] = {}
        for a in impls:
            matrix[a] = {}
            for b in impls:
                caps_a = self._advertisements[a]
                caps_b = self._advertisements[b]
                matrix[a][b] = caps_a.compatibility_score(caps_b)
        return matrix


# ─── 5. Canonical ISA Store ──────────────────────────────────────────────────

class CanonicalISAStore:
    """
    Immutable record of canonical ISA declarations.

    Each declaration creates a new version. Old versions are never modified.
    This provides an auditable history of all authority decisions.
    """

    def __init__(self) -> None:
        self._versions: List[ISAVersion] = []
        self._current: Optional[ISAVersion] = None

    def declare(
        self, version: str, description: str,
        opcodes: Dict[int, OpcodeEntry]
    ) -> ISAVersion:
        """Declare a new canonical ISA version."""
        isa = ISAVersion(
            version=version,
            description=description,
            opcode_count=len(opcodes),
            created_at=time.time(),
            entries=dict(opcodes),
        )
        isa.compute_hash()
        self._versions.append(isa)
        self._current = isa
        return isa

    def get_current(self) -> Optional[ISAVersion]:
        """Get the current canonical ISA version."""
        return self._current

    def get_version(self, version: str) -> Optional[ISAVersion]:
        """Get a specific ISA version by name."""
        for v in self._versions:
            if v.version == version:
                return v
        return None

    def list_versions(self) -> List[str]:
        """List all declared ISA versions."""
        return [v.version for v in self._versions]

    def diff(self, v1: str, v2: str) -> Dict[str, Any]:
        """Compare two ISA versions and return differences."""
        iv1 = self.get_version(v1)
        iv2 = self.get_version(v2)
        if not iv1 or not iv2:
            return {"error": "Version not found"}

        added = set(iv2.entries.keys()) - set(iv1.entries.keys())
        removed = set(iv1.entries.keys()) - set(iv2.entries.keys())
        changed = {}
        for code in set(iv1.entries.keys()) & set(iv2.entries.keys()):
            e1, e2 = iv1.entries[code], iv2.entries[code]
            if e1.mnemonic != e2.mnemonic or e1.format != e2.format:
                changed[code] = {
                    "from": {"mnemonic": e1.mnemonic, "format": e1.format},
                    "to": {"mnemonic": e2.mnemonic, "format": e2.format},
                }

        return {
            "version_a": v1,
            "version_b": v2,
            "added": sorted(added),
            "removed": sorted(removed),
            "changed": {f"0x{k:02X}": v for k, v in sorted(changed.items())},
            "summary": f"{len(added)} added, {len(removed)} removed, {len(changed)} changed",
        }


# ─── 6. Migration Planner ────────────────────────────────────────────────────

@dataclass
class MigrationStep:
    """A single migration step."""
    from_opcode: int
    from_mnemonic: str
    to_opcode: int
    to_mnemonic: str
    reason: str


class MigrationPlanner:
    """
    Automated migration planning when opcodes change between ISA versions.

    Generates step-by-step migration instructions that can be applied to
    existing bytecode programs to bring them up to a new ISA version.
    """

    def __init__(self, store: CanonicalISAStore) -> None:
        self.store = store

    def plan(self, from_version: str, to_version: str) -> List[MigrationStep]:
        """Generate migration plan from one ISA version to another."""
        diff = self.store.diff(from_version, to_version)
        if "error" in diff:
            return []

        steps = []
        v_from = self.store.get_version(from_version)
        v_to = self.store.get_version(to_version)

        # Handle removed opcodes
        for code in diff.get("removed", []):
            entry = v_from.entries.get(code)
            if entry:
                steps.append(MigrationStep(
                    from_opcode=code,
                    from_mnemonic=entry.mnemonic,
                    to_opcode=code,
                    to_mnemonic="REMOVED",
                    reason=f"Opcode 0x{code:02X} ({entry.mnemonic}) removed in {to_version}",
                ))

        # Handle changed opcodes
        for code_str, change in diff.get("changed", {}).items():
            code = int(code_str, 16)
            steps.append(MigrationStep(
                from_opcode=code,
                from_mnemonic=change["from"]["mnemonic"],
                to_opcode=code,
                to_mnemonic=change["to"]["mnemonic"],
                reason=f"Opcode 0x{code:02X} changed from {change['from']['mnemonic']} to {change['to']['mnemonic']}",
            ))

        return steps

    def plan_summary(self, steps: List[MigrationStep]) -> str:
        """Generate a human-readable migration plan summary."""
        if not steps:
            return "No migration steps needed — ISA versions are compatible."
        lines = [f"Migration Plan: {len(steps)} steps"]
        for i, step in enumerate(steps, 1):
            lines.append(
                f"  {i}. 0x{step.from_opcode:02X} {step.from_mnemonic} -> "
                f"0x{step.to_opcode:02X} {step.to_mnemonic}: {step.reason}"
            )
        return "\n".join(lines)


# ─── Convenience Functions ────────────────────────────────────────────────────

def create_authority() -> Tuple[OpcodeRegistry, ConflictDetector, ArbitrationEngine]:
    """Create a complete ISA authority with default configuration."""
    registry = OpcodeRegistry()
    detector = ConflictDetector(registry)
    engine = ArbitrationEngine(registry)
    return registry, detector, engine


def quick_conflict_check(
    impl_a: str, opcodes_a: List[OpcodeEntry],
    impl_b: str, opcodes_b: List[OpcodeEntry],
) -> List[ConflictRecord]:
    """Quick conflict check between two implementations."""
    registry = OpcodeRegistry()
    registry.register_implementation(impl_a, opcodes_a)
    registry.register_implementation(impl_b, opcodes_b)
    detector = ConflictDetector(registry)
    return detector.find_all_conflicts()
