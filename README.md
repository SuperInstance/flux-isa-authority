# flux-isa-authority

ISA Governance Layer for the FLUX Virtual Machine Ecosystem.

## Purpose

The ISA Authority Arbiter resolves the critical problem discovered during
Session 7: **fatal opcode numbering conflicts between VM implementations**.
When the Python VM (flux-runtime) and Go VM (greenhorn-runtime) assign
different opcode numbers to the same instruction, compiled bytecode becomes
unrunnable across implementations.

This module provides:

1. **Opcode Registry** — Single source of truth for opcode → instruction mapping
2. **Conflict Detector** — Automated detection of opcode divergence between implementations
3. **Arbitration Engine** — Evidence-based conflict resolution with voting
4. **Version Negotiation** — Runtime ISA version capability exchange
5. **Canonical Declaration** — Formal process for establishing the authoritative mapping
6. **Migration Guides** — Automated migration plans when opcodes change

## Architecture

```
┌─────────────────────────────────────────────┐
│              ISA Authority Arbiter           │
├──────────┬──────────┬───────────┬───────────┤
│  Opcode  │ Conflict │ Arbitration│  Version  │
│ Registry │ Detector │  Engine   │ Negotiator│
├──────────┴──────────┴───────────┴───────────┤
│           Canonical ISA Store                │
├─────────────────────────────────────────────┤
│  flux-runtime  │  greenhorn  │  flux-vm-ts  │
│  (Python)      │  (Go)       │  (TypeScript)│
└─────────────────────────────────────────────┘
```

## Usage

```python
from isa_authority import OpcodeRegistry, ConflictDetector, ArbitrationEngine

registry = OpcodeRegistry()
registry.register_implementation("python-vm", python_opcodes)
registry.register_implementation("go-vm", go_opcodes)

detector = ConflictDetector(registry)
conflicts = detector.find_conflicts()

engine = ArbitrationEngine(registry)
resolution = engine.arbitrate(conflicts[0])
```

## Author

Quill (Architect-rank) — Session 7b R&D Round 14

## License

MIT
