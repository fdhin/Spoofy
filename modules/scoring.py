# modules/scoring.py

"""
Weighted scoring engine for email security posture.

Computes a 0-100 score and A+→F letter grade per domain based on:
  - SPF configuration (18 pts)
  - DMARC configuration (25 pts)
  - DKIM presence & key strength (15 pts)
  - BIMI presence (5 pts)
  - Spoofability verdict (15 pts)
  - MTA-STS & TLS-RPT (10 pts)
  - MX infrastructure (7 pts)
  - DNSSEC (5 pts)
"""


class SecurityScore:
    """Calculates a weighted security score for a domain's email configuration."""

    # Grade boundaries
    GRADE_BOUNDARIES = [
        (95, "A+"),
        (90, "A"),
        (85, "A-"),
        (80, "B+"),
        (75, "B"),
        (70, "B-"),
        (65, "C+"),
        (60, "C"),
        (55, "C-"),
        (50, "D+"),
        (45, "D"),
        (40, "D-"),
        (0, "F"),
    ]

    def __init__(self, result):
        """
        Initialize with a result dict from process_domain().

        Args:
            result: dict with keys like SPF, DMARC, DKIM, BIMI_RECORD,
                    SPOOFING_POSSIBLE, MTA_STS_MODE, MX_RECORDS, etc.
        """
        self.result = result
        self.breakdown = {}
        self.score = self._calculate_score()
        self.grade = self._calculate_grade()

    def _calculate_score(self):
        """Calculate the total weighted score (0-100)."""
        spf_score = self._score_spf()
        dmarc_score = self._score_dmarc()
        dkim_score = self._score_dkim()
        bimi_score = self._score_bimi()
        spoof_score = self._score_spoofability()
        mta_sts_score = self._score_mta_sts()
        mx_score = self._score_mx()
        dnssec_score = self._score_dnssec()

        self.breakdown = {
            "spf": {"score": spf_score, "max": 18, "details": self._spf_details()},
            "dmarc": {"score": dmarc_score, "max": 25, "details": self._dmarc_details()},
            "dkim": {"score": dkim_score, "max": 15, "details": self._dkim_details()},
            "bimi": {"score": bimi_score, "max": 5, "details": self._bimi_details()},
            "spoofability": {"score": spoof_score, "max": 15, "details": self._spoof_details()},
            "mta_sts": {"score": mta_sts_score, "max": 10, "details": self._mta_sts_details()},
            "mx": {"score": mx_score, "max": 7, "details": self._mx_details()},
            "dnssec": {"score": dnssec_score, "max": 5, "details": self._dnssec_details()},
        }

        return (spf_score + dmarc_score + dkim_score + bimi_score
                + spoof_score + mta_sts_score + mx_score + dnssec_score)

    def _score_spf(self):
        """Score SPF configuration (0-18 points)."""
        score = 0
        spf = self.result.get("SPF")
        spf_all = self.result.get("SPF_MULTIPLE_ALLS")
        too_many = self.result.get("SPF_TOO_MANY_DNS_QUERIES", False)

        if not spf:
            return 0

        # Record exists (+5)
        score += 5

        # Valid syntax — basic check: starts with v=spf1 (+3)
        if spf.strip().lower().startswith("v=spf1"):
            score += 3

        # Strong all mechanism: -all (+8), ~all (+4), ?all (+1), +all (0)
        if spf_all == "-all":
            score += 8
        elif spf_all == "~all":
            score += 4
        elif spf_all == "?all":
            score += 1

        # DNS lookup count within limit (+2)
        if not too_many:
            score += 2

        return min(score, 18)

    def _score_dmarc(self):
        """Score DMARC configuration (0-25 points)."""
        score = 0
        dmarc = self.result.get("DMARC")
        policy = self.result.get("DMARC_POLICY")
        pct = self.result.get("DMARC_PCT")
        rua = self.result.get("DMARC_AGGREGATE_REPORT")
        sp = self.result.get("DMARC_SP")

        if not dmarc:
            return 0

        # Record exists (+3)
        score += 3

        # Valid syntax — starts with v=DMARC1 (+2)
        if "DMARC1" in str(dmarc):
            score += 2

        # Policy strength: reject (+10), quarantine (+7), none (+2)
        if policy == "reject":
            score += 10
        elif policy == "quarantine":
            score += 7
        elif policy == "none":
            score += 2

        # Percentage = 100 or not set (defaults to 100) (+3)
        if pct is None or str(pct).strip() == "100":
            score += 3
        elif pct:
            try:
                score += int(int(pct) * 3 / 100)
            except (ValueError, TypeError):
                pass

        # Aggregate reporting configured (+4)
        if rua:
            score += 4

        # Subdomain policy (+3)
        if sp in ("reject", "quarantine"):
            score += 3
        elif sp == "none":
            score += 1

        return min(score, 25)

    def _score_dkim(self):
        """Score DKIM configuration (0-15 points)."""
        score = 0
        dkim = self.result.get("DKIM")
        selectors = self.result.get("DKIM_SELECTORS", [])
        has_weak = self.result.get("DKIM_HAS_WEAK_KEYS", False)

        if not dkim:
            return 0

        # Selectors found (+7)
        score += 7

        # Multiple selectors found (+3) — indicates good key rotation
        if len(selectors) > 1 or (dkim and "\n" in str(dkim)):
            score += 3

        # Key strength: all strong keys (+5), has weak (-3 from full)
        if selectors:
            if not has_weak:
                score += 5
            else:
                score += 2  # Some credit for having DKIM even with weak keys
        else:
            # Legacy: no structured selector data, give partial credit
            score += 3

        return min(score, 15)

    def _score_bimi(self):
        """Score BIMI configuration (0-5 points)."""
        score = 0
        bimi = self.result.get("BIMI_RECORD")
        location = self.result.get("BIMI_LOCATION")
        authority = self.result.get("BIMI_AUTHORITY")

        if not bimi:
            return 0

        # Record exists (+2)
        score += 2

        # Has a valid logo location (+2)
        if location and str(location).strip():
            score += 2

        # Has authority evidence (VMC certificate) (+1)
        if authority and str(authority).strip():
            score += 1

        return min(score, 5)

    def _score_spoofability(self):
        """Score based on spoofability verdict (0-15 points)."""
        spoofable = self.result.get("SPOOFING_POSSIBLE")

        if spoofable is False:
            return 15
        elif spoofable is None:
            return 8
        else:
            return 0

    def _score_mta_sts(self):
        """Score MTA-STS and TLS-RPT configuration (0-10 points)."""
        score = 0
        mta_sts_txt = self.result.get("MTA_STS_TXT")
        mta_sts_mode = self.result.get("MTA_STS_MODE")
        tls_rpt = self.result.get("TLS_RPT_RECORD")

        # MTA-STS TXT exists (+2)
        if mta_sts_txt:
            score += 2

            # Policy mode: enforce (+5), testing (+3), none (+0)
            if mta_sts_mode == "enforce":
                score += 5
            elif mta_sts_mode == "testing":
                score += 3

        # TLS-RPT configured (+3)
        if tls_rpt:
            score += 3

        return min(score, 10)

    def _score_mx(self):
        """Score MX infrastructure (0-7 points)."""
        score = 0
        mx_records = self.result.get("MX_RECORDS", [])
        mx_count = self.result.get("MX_COUNT", 0)
        all_starttls = self.result.get("MX_ALL_STARTTLS")

        if mx_count == 0:
            return 0

        # MX records exist (+2)
        score += 2

        # Multiple MX for redundancy (+2)
        if mx_count >= 2:
            score += 2

        # All MX support STARTTLS (+3)
        if all_starttls is True:
            score += 3
        elif all_starttls is None:
            score += 1  # Could not determine

        return min(score, 7)

    def _score_dnssec(self):
        """Score DNSSEC configuration (0-5 points)."""
        score = 0
        enabled = self.result.get("DNSSEC_ENABLED", False)
        has_ds = self.result.get("DNSSEC_HAS_DS", False)

        if not enabled:
            return 0

        # DNSKEY records present (+3)
        score += 3

        # DS record in parent zone — chain of trust verified (+2)
        if has_ds:
            score += 2

        return min(score, 5)

    def _calculate_grade(self):
        """Convert numeric score to letter grade."""
        for threshold, grade in self.GRADE_BOUNDARIES:
            if self.score >= threshold:
                return grade
        return "F"

    # --- Detail strings for breakdown ---

    def _spf_details(self):
        """Return detail items for SPF scoring."""
        details = []
        spf = self.result.get("SPF")
        spf_all = self.result.get("SPF_MULTIPLE_ALLS")
        too_many = self.result.get("SPF_TOO_MANY_DNS_QUERIES", False)

        if not spf:
            details.append(("❌", "No SPF record found"))
            return details

        details.append(("✅", "SPF record exists"))

        if spf.strip().lower().startswith("v=spf1"):
            details.append(("✅", "Valid SPF syntax"))
        else:
            details.append(("❌", "Invalid SPF syntax"))

        if spf_all == "-all":
            details.append(("✅", "Hard fail (-all) — strongest setting"))
        elif spf_all == "~all":
            details.append(("⚠️", "Soft fail (~all) — consider upgrading to -all"))
        elif spf_all == "?all":
            details.append(("⚠️", "Neutral (?all) — provides no protection"))
        elif spf_all == "+all":
            details.append(("❌", "Pass all (+all) — allows anyone to send"))
        elif spf_all == "2many":
            details.append(("❌", "Multiple 'all' mechanisms found"))
        elif spf_all is None:
            details.append(("⚠️", "No 'all' mechanism found"))

        if too_many:
            details.append(("❌", "Too many DNS lookups (>10)"))
        else:
            details.append(("✅", "DNS lookup count within limit"))

        return details

    def _dmarc_details(self):
        """Return detail items for DMARC scoring."""
        details = []
        dmarc = self.result.get("DMARC")
        policy = self.result.get("DMARC_POLICY")
        pct = self.result.get("DMARC_PCT")
        rua = self.result.get("DMARC_AGGREGATE_REPORT")
        fo = self.result.get("DMARC_FORENSIC_REPORT")
        sp = self.result.get("DMARC_SP")

        if not dmarc:
            details.append(("❌", "No DMARC record found"))
            return details

        details.append(("✅", "DMARC record exists"))

        if policy == "reject":
            details.append(("✅", "Policy: reject — strongest setting"))
        elif policy == "quarantine":
            details.append(("⚠️", "Policy: quarantine — consider upgrading to reject"))
        elif policy == "none":
            details.append(("❌", "Policy: none — no protection against spoofing"))
        else:
            details.append(("❌", "No policy (p=) tag found"))

        if pct is None or str(pct).strip() == "100":
            details.append(("✅", "Policy applies to 100% of messages"))
        else:
            details.append(("⚠️", f"Policy only applies to {pct}% of messages"))

        if rua:
            details.append(("✅", f"Aggregate reports configured: {rua}"))
        else:
            details.append(("⚠️", "No aggregate report (rua) configured"))

        if fo:
            details.append(("✅", f"Forensic reports configured: {fo}"))

        if sp:
            if sp in ("reject", "quarantine"):
                details.append(("✅", f"Subdomain policy: {sp}"))
            else:
                details.append(("⚠️", f"Subdomain policy: {sp}"))
        else:
            details.append(("⚠️", "No subdomain policy (sp=) — inherits p= value"))

        return details

    def _dkim_details(self):
        """Return detail items for DKIM scoring."""
        details = []
        dkim = self.result.get("DKIM")
        selectors = self.result.get("DKIM_SELECTORS", [])
        has_weak = self.result.get("DKIM_HAS_WEAK_KEYS", False)

        if not dkim:
            details.append(("⚠️", "No DKIM selectors found"))
            return details

        count = len(selectors) if selectors else str(dkim).count("[*]")
        details.append(("✅", f"{count} DKIM selector(s) found"))

        if count > 1:
            details.append(("✅", "Multiple selectors — good key rotation practice"))

        if selectors:
            for sel in selectors:
                bits = sel.get("key_bits")
                if bits:
                    if bits >= 2048:
                        details.append(("✅", f"{sel['selector']}: {bits}-bit key (strong)"))
                    else:
                        details.append(("❌", f"{sel['selector']}: {bits}-bit key (weak — upgrade to 2048+)"))
        elif has_weak:
            details.append(("❌", "One or more DKIM keys are < 2048 bits"))

        return details

    def _bimi_details(self):
        """Return detail items for BIMI scoring."""
        details = []
        bimi = self.result.get("BIMI_RECORD")
        location = self.result.get("BIMI_LOCATION")
        authority = self.result.get("BIMI_AUTHORITY")

        if not bimi:
            details.append(("ℹ️", "No BIMI record found (optional)"))
            return details

        details.append(("✅", "BIMI record exists"))

        if location and str(location).strip():
            details.append(("✅", f"Logo location: {location}"))
        else:
            details.append(("⚠️", "No logo location specified"))

        if authority and str(authority).strip():
            details.append(("✅", f"VMC authority: {authority}"))
        else:
            details.append(("ℹ️", "No VMC certificate (authority) specified"))

        return details

    def _spoof_details(self):
        """Return detail items for spoofability."""
        details = []
        spoofable = self.result.get("SPOOFING_POSSIBLE")
        spoof_type = self.result.get("SPOOFING_TYPE", "")

        if spoofable is False:
            details.append(("✅", "Domain is not spoofable"))
        elif spoofable is None:
            details.append(("⚠️", "Spoofing may be possible depending on mailbox"))
        else:
            details.append(("❌", "Domain is spoofable"))

        if spoof_type:
            details.append(("ℹ️", spoof_type))

        return details

    def _mta_sts_details(self):
        """Return detail items for MTA-STS & TLS-RPT scoring."""
        details = []
        mta_sts_txt = self.result.get("MTA_STS_TXT")
        mta_sts_mode = self.result.get("MTA_STS_MODE")
        max_age = self.result.get("MTA_STS_MAX_AGE")
        tls_rpt = self.result.get("TLS_RPT_RECORD")
        tls_rpt_rua = self.result.get("TLS_RPT_RUA")

        if not mta_sts_txt:
            details.append(("⚠️", "No MTA-STS record found"))
        else:
            details.append(("✅", "MTA-STS TXT record exists"))

            if mta_sts_mode == "enforce":
                details.append(("✅", "MTA-STS mode: enforce — TLS required"))
            elif mta_sts_mode == "testing":
                details.append(("⚠️", "MTA-STS mode: testing — not enforced yet"))
            elif mta_sts_mode == "none":
                details.append(("❌", "MTA-STS mode: none — no protection"))
            else:
                details.append(("⚠️", f"MTA-STS mode: {mta_sts_mode}"))

            if max_age:
                if isinstance(max_age, int) and max_age >= 86400:
                    details.append(("✅", f"Max age: {max_age}s ({max_age // 86400}d)"))
                else:
                    details.append(("⚠️", f"Max age: {max_age}s (consider ≥ 86400)"))

        if tls_rpt:
            details.append(("✅", f"TLS-RPT configured"))
            if tls_rpt_rua:
                details.append(("✅", f"TLS reports sent to: {tls_rpt_rua}"))
        else:
            details.append(("⚠️", "No TLS-RPT record found"))

        return details

    def _mx_details(self):
        """Return detail items for MX infrastructure scoring."""
        details = []
        mx_records = self.result.get("MX_RECORDS", [])
        mx_count = self.result.get("MX_COUNT", 0)
        providers = self.result.get("MX_PROVIDERS", [])
        all_starttls = self.result.get("MX_ALL_STARTTLS")
        all_ptr = self.result.get("MX_ALL_PTR")

        if mx_count == 0:
            details.append(("⚠️", "No MX records found"))
            return details

        details.append(("✅", f"{mx_count} MX record(s) found"))

        if providers:
            details.append(("ℹ️", f"Provider(s): {', '.join(providers)}"))

        if mx_count >= 2:
            details.append(("✅", "Multiple MX records for redundancy"))
        else:
            details.append(("⚠️", "Single MX — consider adding redundancy"))

        if all_starttls is True:
            details.append(("✅", "All MX hosts support STARTTLS"))
        elif all_starttls is False:
            details.append(("❌", "Not all MX hosts support STARTTLS"))
        else:
            details.append(("ℹ️", "STARTTLS status could not be fully determined"))

        if all_ptr is True:
            details.append(("✅", "All MX hosts have valid PTR records"))
        elif all_ptr is False:
            details.append(("⚠️", "Not all MX hosts have valid PTR records"))

        return details

    def _dnssec_details(self):
        """Return detail items for DNSSEC scoring."""
        details = []
        enabled = self.result.get("DNSSEC_ENABLED", False)
        has_ds = self.result.get("DNSSEC_HAS_DS", False)
        key_count = self.result.get("DNSSEC_KEY_COUNT", 0)

        if not enabled:
            details.append(("⚠️", "DNSSEC is not enabled"))
            return details

        details.append(("✅", f"DNSSEC enabled ({key_count} DNSKEY record(s))"))

        if has_ds:
            details.append(("✅", "DS record found — chain of trust verified"))
        else:
            details.append(("⚠️", "No DS record in parent zone — chain of trust incomplete"))

        return details

    def to_dict(self):
        """Return score data as a dictionary for inclusion in results."""
        return {
            "SECURITY_SCORE": self.score,
            "SECURITY_GRADE": self.grade,
            "SCORE_BREAKDOWN": {
                category: {
                    "score": data["score"],
                    "max": data["max"],
                    "percentage": round(data["score"] / data["max"] * 100)
                    if data["max"] > 0
                    else 0,
                }
                for category, data in self.breakdown.items()
            },
            "SCORE_DETAILS": {
                category: data["details"]
                for category, data in self.breakdown.items()
            },
        }

    def __str__(self):
        lines = [
            f"Security Score: {self.score}/100 ({self.grade})",
            "",
        ]
        for category, data in self.breakdown.items():
            lines.append(
                f"  {category.upper()}: {data['score']}/{data['max']} pts"
            )
            for icon, detail in data["details"]:
                lines.append(f"    {icon} {detail}")
            lines.append("")
        return "\n".join(lines)
