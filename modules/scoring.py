# modules/scoring.py

"""
Weighted scoring engine for email security posture.

Computes a 0-100 score and A+→F letter grade per domain based on:
  - SPF configuration (16 pts)
  - DMARC configuration (22 pts)
  - DKIM presence & key strength (15 pts) — excluded if not scanned
  - BIMI presence (5 pts)
  - CAA configuration (5 pts)
  - Spoofability verdict (15 pts)
  - MTA-STS & TLS-RPT (10 pts)
  - MX infrastructure (7 pts) — STARTTLS portion excluded if not scanned
  - DNSSEC (5 pts)
  - DANE (5 pts)

When optional scan features (DKIM, STARTTLS) are disabled, the max
possible score is reduced proportionally. Grade boundaries use the
percentage of max, so grades are comparable across scan modes.
"""

from .spf import _is_spf_record

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
        """Calculate the total weighted score.

        When optional features (DKIM, STARTTLS) aren't scanned, their max
        is excluded so the percentage-based grade stays honest across modes.
        """
        dkim_scanned = self.result.get("DKIM_SCANNED", True)
        starttls_scanned = self.result.get("STARTTLS_SCANNED", True)

        spf_score = self._score_spf()
        dmarc_score = self._score_dmarc()
        dkim_score = self._score_dkim() if dkim_scanned else None
        bimi_score = self._score_bimi()
        caa_score = self._score_caa()
        spoof_score = self._score_spoofability()
        mta_sts_score = self._score_mta_sts()
        mx_score = self._score_mx()
        dnssec_score = self._score_dnssec()
        dane_score = self._score_dane()

        # MX max is 7 normally; STARTTLS contributes 3 of those points.
        # When STARTTLS isn't scanned, reduce MX max by 3.
        mx_max = 7 if starttls_scanned else 4

        self.breakdown = {
            "spf": {"score": spf_score, "max": 16, "details": self._spf_details()},
            "dmarc": {"score": dmarc_score, "max": 22, "details": self._dmarc_details()},
            "dkim": {"score": dkim_score, "max": 15 if dkim_scanned else 0,
                     "details": self._dkim_details()},
            "bimi": {"score": bimi_score, "max": 5, "details": self._bimi_details()},
            "caa": {"score": caa_score, "max": 5, "details": self._caa_details()},
            "spoofability": {"score": spoof_score, "max": 15, "details": self._spoof_details()},
            "mta_sts": {"score": mta_sts_score, "max": 10, "details": self._mta_sts_details()},
            "mx": {"score": mx_score, "max": mx_max, "details": self._mx_details()},
            "dnssec": {"score": dnssec_score, "max": 5, "details": self._dnssec_details()},
            "dane": {"score": dane_score, "max": 5, "details": self._dane_details()},
        }

        # Sum only categories that were actually scanned
        total = spf_score + dmarc_score + bimi_score + caa_score
        total += spoof_score + mta_sts_score + mx_score + dnssec_score + dane_score
        if dkim_score is not None:
            total += dkim_score

        # Compute max possible score
        self.max_score = sum(d["max"] for d in self.breakdown.values())

        return total

    def _score_spf(self):
        """Score SPF configuration (0-16 points).

        Per RFC 7208:
        - §4.5: Multiple SPF records cause PermError (hard-cap at 0).
        - §4.6.4: Exceeding 10 DNS lookups causes PermError (hard-cap at 5,
          record exists but provides no protection).
        """
        score = 0
        spf = self.result.get("SPF")
        spf_all = self.result.get("SPF_MULTIPLE_ALLS")
        too_many = self.result.get("SPF_TOO_MANY_DNS_QUERIES", False)
        permerror = self.result.get("SPF_PERMERROR", False)

        if not spf:
            return 0

        # RFC 7208 §4.5: multiple SPF records = PermError.
        # MTAs abort before even reading the record. Zero protection.
        if permerror:
            return 0

        # Record exists (+5)
        score += 5

        # RFC 7208 PermError: >10 lookups aborts SPF check entirely.
        # The record exists (credit for that) but provides no protection.
        if too_many:
            return 5

        # Valid syntax — strict check per RFC 7208 §4.5 (+3)
        if _is_spf_record(spf):
            score += 3

        # Strong all mechanism: -all (+6), ~all (+4), ?all (+1), +all (0)
        if spf_all == "-all":
            score += 6
        elif spf_all == "~all":
            score += 4
        elif spf_all == "?all":
            score += 1

        # DNS lookup count within limit (+2)
        score += 2

        return min(score, 16)

    def _score_dmarc(self):
        """Score DMARC configuration (0-22 points)."""
        score = 0
        dmarc = self.result.get("DMARC")
        policy = self.result.get("DMARC_POLICY")
        pct = self.result.get("DMARC_PCT")
        rua = self.result.get("DMARC_AGGREGATE_REPORT")
        sp = self.result.get("DMARC_SP")
        wildcard_dns = self.result.get("DMARC_HAS_WILDCARD_DNS", False)

        if not dmarc:
            return 0

        # Record exists (+3)
        score += 3

        # Valid syntax — starts with v=DMARC1 (+2)
        if str(dmarc).strip().startswith("v=DMARC1"):
            score += 2

        # Policy strength: reject (+8), quarantine (+5), none (+1)
        if policy == "reject":
            score += 8
        elif policy == "quarantine":
            score += 5
        elif policy == "none":
            score += 1

        # Percentage = 100 or not set (defaults to 100) (+2)
        if pct is None or str(pct).strip() == "100":
            score += 2

        # Aggregate reporting configured (+4)
        if rua:
            score += 4

        # Subdomain policy (+3)
        if sp in ("reject", "quarantine"):
            score += 3
        elif sp == "none":
            score += 1

        # Penalty for wildcard DNS Subdomain Hijacking
        # Effective subdomain policy: sp overrides p for subdomains (RFC 7489 §6.3)
        effective_sp = sp if sp else policy
        if wildcard_dns and effective_sp != "reject":
            score -= 5

        return max(0, min(score, 22))

    def _score_dkim(self):
        """Score DKIM configuration (0-15 points).

        Only usable selectors (valid version, not revoked, applicable for email)
        contribute to the score. Testing-mode keys are penalized per RFC 6376 §3.6.1.
        """
        score = 0
        dkim = self.result.get("DKIM")
        selectors = self.result.get("DKIM_SELECTORS", [])
        has_weak = self.result.get("DKIM_HAS_WEAK_KEYS", False)

        if not dkim:
            return 0

        # Count only usable selectors for scoring
        usable = [s for s in selectors if s.get("is_usable", True)]

        if not usable:
            # All selectors are revoked/invalid/non-email — no credit
            return 0

        # Usable selectors found (+7)
        score += 7

        # Multiple usable selectors found (+3) — indicates good key rotation
        if len(usable) > 1:
            score += 3

        # Key strength: all strong keys (+5), has weak (-3 from full)
        if not has_weak:
            score += 5
        else:
            score += 2  # Some credit for having DKIM even with weak keys

        # Penalty: all usable selectors are in testing mode (-2)
        # RFC 6376 §3.6.1: verifiers MUST NOT treat testing-mode differently from unsigned
        if all(s.get("is_testing", False) for s in usable):
            score = max(score - 2, 0)

        return min(score, 15)

    def _score_bimi(self):
        """Score BIMI configuration (0-5 points).

        Note: BIMI points are awarded regardless of DMARC policy. The BIMI
        record itself is valid even with p=none, though receivers won't
        render the logo without quarantine/reject. The _bimi_details()
        method flags this dependency.
        """
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

    def _score_caa(self):
        """Score CAA configuration (0-5 points)."""
        caa = self.result.get("CAA_RECORDS", [])
        has_issue = self.result.get("CAA_HAS_ISSUE", False)
        
        if not caa:
            return 0
            
        score = 2 # Exists
        
        if has_issue:
            score += 3
            
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
        """Score MTA-STS and TLS-RPT configuration (0-10 points).

        Null MX (RFC 7505) domains intentionally receive no email, so
        MTA-STS and TLS-RPT are inapplicable — award full points.
        """
        # Null MX exemption: domain doesn't receive mail
        if self.result.get("MX_HAS_NULL_MX", False):
            return 10

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
        """Score MX infrastructure (0-7 points).

        When STARTTLS is not scanned, the STARTTLS portion (3 pts) is
        excluded from both the score and the max.
        """
        score = 0
        mx_count = self.result.get("MX_COUNT", 0)
        all_starttls = self.result.get("MX_ALL_STARTTLS")
        has_null_mx = self.result.get("MX_HAS_NULL_MX", False)
        starttls_scanned = self.result.get("STARTTLS_SCANNED", True)

        if mx_count == 0:
            return 0

        if has_null_mx:
            # Null MX is correct config — full points for what was scanned
            return 7 if starttls_scanned else 4

        # MX records exist (+2)
        score += 2

        # Multiple MX for redundancy (+2)
        if mx_count >= 2:
            score += 2

        # All MX support STARTTLS (+3) — only if scanned
        if starttls_scanned:
            if all_starttls is True:
                score += 3
            elif all_starttls is None:
                score += 1  # Could not determine

        max_score = 7 if starttls_scanned else 4
        return min(score, max_score)

    def _score_dnssec(self):
        """Score DNSSEC configuration (0-5 points)."""
        score = 0
        enabled = self.result.get("DNSSEC_ENABLED", False)
        dnskey_present = self.result.get("DNSSEC_DNSKEY_PRESENT", False)
        has_ds = self.result.get("DNSSEC_HAS_DS", False)
        ad_flag = self.result.get("DNSSEC_AD_FLAG", False)

        if not dnskey_present and not has_ds:
            return 0

        # DNSKEY records present (+1 partial credit even without DS)
        if dnskey_present:
            score += 1

        # Full chain of trust: DNSKEY + DS (+2)
        if enabled:
            # Penalize deprecated cryptography (e.g. SHA-1) per RFC 9904
            if self.result.get("DNSSEC_HAS_WEAK_DNSKEY") or self.result.get("DNSSEC_HAS_WEAK_DS"):
                score += 1
            else:
                score += 2

        # AD flag validated by recursive resolver (+2)
        if ad_flag:
            score += 2

        return min(score, 5)

    def _calculate_grade(self):
        """Convert numeric score to letter grade.

        Uses percentage of max_score so grades are comparable across
        scan modes (e.g. with/without --dkim).
        """
        max_score = getattr(self, "max_score", 100) or 100
        pct = (self.score / max_score) * 100
        for threshold, grade in self.GRADE_BOUNDARIES:
            if pct >= threshold:
                return grade
        return "F"

    # --- Detail strings for breakdown ---

    def _spf_details(self):
        """Return detail items for SPF scoring."""
        details = []
        spf = self.result.get("SPF")
        spf_all = self.result.get("SPF_MULTIPLE_ALLS")
        too_many = self.result.get("SPF_TOO_MANY_DNS_QUERIES", False)
        permerror = self.result.get("SPF_PERMERROR", False)

        if not spf:
            details.append(("❌", "No SPF record found"))
            return details

        details.append(("✅", "SPF record exists"))

        # PermError from multiple records overrides everything
        if permerror:
            details.append(("❌", "CRITICAL: Multiple SPF records published — "
                           "MTAs return PermError and abort SPF evaluation "
                           "(RFC 7208 §4.5)"))
            return details

        if _is_spf_record(spf):
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
            
        macros = self.result.get("SPF_MACROS", [])
        if macros:
            details.append(("ℹ️", f"SPF uses advanced macros: {', '.join(macros)}"))

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
            
        wildcard_dns = self.result.get("DMARC_HAS_WILDCARD_DNS", False)
        if wildcard_dns:
            effective_sp = sp if sp else policy
            if effective_sp != "reject":
                details.append(("❗️", "Wildcard DNS detected without reject subdomain policy. High risk of subdomain spoofing!"))
            else:
                details.append(("✅", "Wildcard DNS detected, but protected by reject policy."))

        return details

    def _dkim_details(self):
        """Return detail items for DKIM scoring."""
        details = []
        dkim_scanned = self.result.get("DKIM_SCANNED", True)
        dkim = self.result.get("DKIM")
        selectors = self.result.get("DKIM_SELECTORS", [])

        if not dkim_scanned:
            details.append(("ℹ️", "DKIM was not scanned (use --dkim to enable)"))
            return details

        if not dkim:
            details.append(("⚠️", "No DKIM selectors found"))
            return details

        usable = [s for s in selectors if s.get("is_usable", True)]
        count = len(usable)
        total = len(selectors)

        if count == 0:
            details.append(("❌", f"{total} selector(s) found but none are usable for email"))
        else:
            details.append(("✅", f"{count} usable DKIM selector(s) found"))

        if count > 1:
            details.append(("✅", "Multiple selectors — good key rotation practice"))

        for sel in selectors:
            name = sel.get("selector", "unknown")

            if sel.get("is_revoked"):
                details.append(("⚠️", f"{name}: key is REVOKED (empty p= tag)"))
                continue

            if not sel.get("is_valid_version", True):
                details.append(("⚠️", f"{name}: invalid key record version, discarded"))
                continue

            if not sel.get("is_email_applicable", True):
                details.append(("ℹ️", f"{name}: not applicable for email (s= tag)"))
                continue

            if sel.get("is_testing"):
                details.append(("⚠️", f"{name}: testing mode (t=y) — verifiers treat as unsigned"))

            bits = sel.get("key_bits")
            key_type = sel.get("key_type", "rsa")
            if bits:
                if key_type == "ed25519":
                    details.append(("✅", f"{name}: Ed25519 key ({bits}-bit, strong)"))
                elif bits >= 2048:
                    details.append(("✅", f"{name}: {bits}-bit {key_type} key (strong)"))
                else:
                    details.append(("❌", f"{name}: {bits}-bit {key_type} key (weak — upgrade to 2048+)"))

            if sel.get("is_sha1_only"):
                details.append(("⚠️", f"{name}: restricted to SHA-1 only (h=sha1) — SHA-256 recommended"))

            if sel.get("is_strict"):
                details.append(("ℹ️", f"{name}: strict subdomain mode (t=s) — i= must exactly match d="))

        return details

    def _bimi_details(self):
        """Return detail items for BIMI scoring."""
        details = []
        bimi = self.result.get("BIMI_RECORD")
        location = self.result.get("BIMI_LOCATION")
        authority = self.result.get("BIMI_AUTHORITY")
        dmarc_policy = self.result.get("DMARC_POLICY")
        dmarc_pct = self.result.get("DMARC_PCT")

        if not bimi:
            details.append(("ℹ️", "No BIMI record found (optional)"))
            return details

        details.append(("✅", "BIMI record exists"))

        # BIMI requires DMARC quarantine/reject for receivers to render the logo
        if dmarc_policy not in ("quarantine", "reject"):
            details.append(("⚠️", "BIMI is decorative without DMARC enforcement (p=quarantine or p=reject) — receivers will not render the logo"))

        # BIMI requires pct=100 (RFC 8965 §3.1.1)
        # Receivers like Gmail and Apple will not display the logo if pct < 100
        if dmarc_pct is not None and str(dmarc_pct).strip() != "100":
            details.append(("⚠️", f"BIMI requires DMARC pct=100 for logo display — current pct={dmarc_pct}"))

        if location and str(location).strip():
            details.append(("✅", f"Logo location: {location}"))
        else:
            details.append(("⚠️", "No logo location specified"))

        if authority and str(authority).strip():
            details.append(("✅", f"VMC authority: {authority}"))
        else:
            details.append(("ℹ️", "No VMC certificate (authority) specified"))

        return details

    def _caa_details(self):
        """Return detail items for CAA scoring."""
        details = []
        caa = self.result.get("CAA_RECORDS", [])
        has_issue = self.result.get("CAA_HAS_ISSUE", False)

        if not caa:
            details.append(("⚠️", "No CAA record found"))
            return details

        details.append(("✅", "CAA record exists"))

        if has_issue:
            details.append(("✅", "CAA restricts issuance to specific authorities"))
        else:
            details.append(("⚠️", "CAA does not explicitly restrict certificate issuance"))

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

        # Null MX exemption: domain doesn't receive mail
        if self.result.get("MX_HAS_NULL_MX", False):
            details.append(("✅", "Null MX — domain does not receive email, MTA-STS/TLS-RPT not applicable"))
            return details

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
        elif not self.result.get("MX_HAS_NULL_MX"):
            details.append(("ℹ️", "STARTTLS status could not be fully determined"))

        if all_ptr is True:
            details.append(("✅", "All MX hosts have valid PTR records (FCrDNS pass)"))
        elif all_ptr is False:
            details.append(("⚠️", "Not all MX hosts have valid PTR records (FCrDNS fail)"))
            
        if self.result.get("MX_HAS_NULL_MX"):
            details.append(("✅", "Null MX configuration detected — domain intentionally receives no email"))

        return details

    def _dnssec_details(self):
        """Return detail items for DNSSEC scoring."""
        details = []
        enabled = self.result.get("DNSSEC_ENABLED", False)
        dnskey_present = self.result.get("DNSSEC_DNSKEY_PRESENT", False)
        has_ds = self.result.get("DNSSEC_HAS_DS", False)
        ad_flag = self.result.get("DNSSEC_AD_FLAG", False)
        key_count = self.result.get("DNSSEC_KEY_COUNT", 0)
        has_dane = self.result.get("DANE_HAS_TLSA", False)
        has_weak_dnskey = self.result.get("DNSSEC_HAS_WEAK_DNSKEY", False)
        has_weak_ds = self.result.get("DNSSEC_HAS_WEAK_DS", False)

        if not dnskey_present and not has_ds:
            details.append(("⚠️", "DNSSEC is not enabled"))
            if has_dane:
                details.append(("❌", "DANE TLSA records exist but DNSSEC is absent — TLSA is ineffective without DNSSEC"))
            return details

        if enabled:
            details.append(("✅", f"DNSSEC enabled ({key_count} DNSKEY record(s))"))
            details.append(("✅", "DS record found — chain of trust verified"))
        elif dnskey_present and not has_ds:
            details.append(("❌", f"DNSSEC broken — {key_count} DNSKEY record(s) but no DS in parent zone"))
            details.append(("❌", "Chain of trust is incomplete — validating resolvers will NOT trust this zone"))
        elif has_ds and not dnskey_present:
            details.append(("❌", "CRITICAL OUTAGE: DS record exists but no valid DNSKEY found!"))
            details.append(("❌", "Validating resolvers (1.1.1.1, 8.8.8.8) will return SERVFAIL and block all access to your domain."))

        # RFC 9904: Flag weak/deprecated cryptographic algorithms
        if has_weak_dnskey:
            details.append(("❌", "DNSKEY uses a deprecated algorithm (RFC 9904) — vulnerable to cryptographic attacks"))
        if has_weak_ds:
            details.append(("❌", "DS record uses a weak digest type (e.g. SHA-1) — RFC 9904 MUST NOT for delegation"))

        if ad_flag:
            details.append(("✅", "AD flag validated — recursive resolver confirms DNSSEC chain"))
        elif enabled:
            details.append(("⚠️", "AD flag not set — DNSSEC may not be fully operational"))

        return details

    def _score_dane(self):
        """Score DANE configuration (0-5 points)."""
        if self.result.get("MX_HAS_NULL_MX", False):
            return 5  # Exempt parked domains

        score = 0
        has_tlsa = self.result.get("DANE_HAS_TLSA", False)
        is_secure = self.result.get("DANE_IS_SECURE", False)
        has_bogus = self.result.get("DANE_HAS_BOGUS_RECORDS", False)
        dnssec_enabled = self.result.get("DNSSEC_ENABLED", False)

        if has_bogus:
            return 0  # Severe penalty for bogus records
        if not has_tlsa:
            return 0

        score += 2  # TLSA records exist
        if is_secure:
            score += 2  # AD flag present on TLSA
        if dnssec_enabled:
            score += 1  # Origin domain DNSSEC (RFC 7672 compliance)

        return min(score, 5)

    def _dane_details(self):
        """Return detail items for DANE scoring."""
        details = []

        if self.result.get("MX_HAS_NULL_MX", False):
            details.append(("✅", "Null MX detected — DANE/TLSA is not required for parked domains"))
            return details

        has_tlsa = self.result.get("DANE_HAS_TLSA", False)
        is_secure = self.result.get("DANE_IS_SECURE", False)
        has_bogus = self.result.get("DANE_HAS_BOGUS_RECORDS", False)
        dnssec_enabled = self.result.get("DNSSEC_ENABLED", False)
        has_unsupported = self.result.get("DANE_HAS_UNSUPPORTED_RECORDS", False)
        dane_mx_count = self.result.get("DANE_MX_COUNT", 0)
        total_mx = self.result.get("DANE_TOTAL_MX", 0)

        # Bogus check MUST be first — can be True even when has_tlsa is False
        # (the "empty TLSA but SERVFAIL" scenario).
        if has_bogus:
            details.append(("❌", "CRITICAL: DNSSEC validation for TLSA queries is BOGUS (SERVFAIL)"))
            details.append(("❌", "MTAs will abort TLS connections and drop your mail!"))
            return details

        if not has_tlsa:
            details.append(("⚠️", "No DANE/TLSA records found for MX hosts"))
            return details

        if has_unsupported:
            details.append(("⚠️", "Some TLSA records contain unsupported parameters and are unusable"))

        if is_secure:
            details.append(("✅", f"TLSA records validated via DNSSEC ({dane_mx_count}/{total_mx} MX hosts)"))
        else:
            details.append(("❌", "TLSA records exist but are not secured by DNSSEC (AD flag missing)"))

        if not dnssec_enabled:
            details.append(("❌", "Origin domain lacks DNSSEC — per RFC 7672 §3.1.3, MTAs will ignore DANE because the MX delegation is insecure"))
        elif is_secure:
            details.append(("✅", "Origin domain has DNSSEC — MX delegation is secure and DANE is fully active"))

        return details

    def to_dict(self):
        """Return score data as a dictionary for inclusion in results."""
        max_score = getattr(self, "max_score", 100) or 100
        return {
            "SECURITY_SCORE": self.score,
            "SECURITY_SCORE_MAX": max_score,
            "SECURITY_SCORE_PCT": round(self.score / max_score * 100) if max_score > 0 else 0,
            "SECURITY_GRADE": self.grade,
            "SCORE_BREAKDOWN": {
                category: {
                    "score": data["score"] if data["score"] is not None else "N/A",
                    "max": data["max"],
                    "percentage": round(data["score"] / data["max"] * 100)
                    if data["max"] > 0 and data["score"] is not None
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
        max_score = getattr(self, "max_score", 100) or 100
        lines = [
            f"Security Score: {self.score}/{max_score} ({self.grade})",
            "",
        ]
        for category, data in self.breakdown.items():
            score_str = str(data['score']) if data['score'] is not None else "N/A"
            lines.append(
                f"  {category.upper()}: {score_str}/{data['max']} pts"
            )
            for icon, detail in data["details"]:
                lines.append(f"    {icon} {detail}")
            lines.append("")
        return "\n".join(lines)
