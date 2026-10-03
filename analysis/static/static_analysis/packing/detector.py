"""Classifies the packer family behind an already-detected packing indicator.

Packing itself (entropy + structural heuristics) is computed per-format in
`pe/parser.py`, `elf/parser.py`, and `mach_o/parser.py` — this module only
takes those already-computed facts and names the likely packer from known
section-name signatures, shared across every format instead of duplicated
per parser.
"""

from static_analysis.packing.models import PackerFinding

# Ordered so the more specific/well-known signatures are matched first.
_PACKER_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("upx", "UPX"),
    (".aspack", "ASPack"),
    (".petite", "Petite"),
    ("petite", "Petite"),
    (".mpress", "MPRESS"),
    (".themida", "Themida"),
    (".vmp", "VMProtect"),
    (".enigma", "Enigma Protector"),
    (".nsp", "NsPack"),
    (".packed", "Generic Packer"),
)


class PackerDetector:
    """Names a packer family from section-name and entropy indicators."""

    def detect(
        self,
        *,
        is_packed: bool,
        suspicious_section_names: tuple[str, ...] = (),
        high_entropy_sections: tuple[str, ...] = (),
    ) -> PackerFinding:
        if not is_packed:
            return PackerFinding.not_packed()

        packer_name, matched_section = self._match_signature(suspicious_section_names)
        evidence: list[str] = []
        if matched_section:
            evidence.append(f"packer-signature section '{matched_section}'")
        if high_entropy_sections:
            evidence.append(f"high-entropy section(s): {', '.join(sorted(high_entropy_sections))}")
        if not evidence:
            evidence.append("packed heuristic (entropy + structural indicators)")

        # Named-signature match is high confidence; entropy-only ("unknown packer") is
        # a weaker, still-actionable signal for an investigator to follow up on.
        confidence = 0.9 if packer_name else 0.55
        return PackerFinding(
            is_packed=True,
            packer_name=packer_name or "unknown_packer",
            confidence=confidence,
            evidence=tuple(evidence),
        )

    @staticmethod
    def _match_signature(section_names: tuple[str, ...]) -> tuple[str | None, str | None]:
        for name in section_names:
            lowered = name.lower()
            for signature, packer_name in _PACKER_SIGNATURES:
                if signature in lowered:
                    return packer_name, name
        return None, None
