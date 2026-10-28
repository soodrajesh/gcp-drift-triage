# ADR 0001: rules own decisions

**Decision**: category, severity, decision and posture come from deterministic rules. Models write explanations and PR text only.
**Why**: resource names, labels and values are attacker-influenced text. A model that decides "benign, adopt it" can be talked into hiding a public grant.
**Consequence**: unknown attributes are routed to *investigate* rather than guessed; the model adds readability, not coverage.
