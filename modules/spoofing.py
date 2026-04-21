# modules/spoofing.py

"""
Email spoofing feasibility analysis.

Determines whether a domain can be spoofed based on its SPF and DMARC
configuration, using the two-axis evaluation model:

    1. Org-domain axis: Can an attacker spoof the From header as user@example.com?
       Depends on the DMARC policy (p=) and SPF all-mechanism.

    2. Subdomain axis: Can an attacker spoof as user@sub.example.com?
       Depends on the subdomain policy (sp=, defaults to p=) and SPF.

Each axis produces: protected / soft-protected / unprotected.
The final verdict combines both axes.

pct < 100 is a modifier applied *after* the main evaluation: it
downgrades "not spoofable" verdicts because only a fraction of
messages are subject to policy enforcement (RFC 7489 §6.6.4).

References:
    - RFC 7489 §6.3  — Policy discovery and defaults
    - RFC 7489 §6.6.4 — Percentage sampling
    - RFC 7208 §2.6   — SPF 'all' mechanism
"""

import logging

import tldextract

from .syntax import validate_record_syntax

logger = logging.getLogger("spoofyvibe.spoofing")


# Verdict codes — each maps to a human-readable spoofing assessment
VERDICT_SPOOFABLE = 0          # Fully spoofable (no protection)
VERDICT_SUBDOMAIN_SPOOFABLE = 1  # Org domain protected, subdomains spoofable
VERDICT_ORG_SPOOFABLE = 2     # Subdomains protected, org domain spoofable
VERDICT_MAYBE = 3             # Might be spoofable (weak config or pct < 100)
VERDICT_MAILBOX_DEP = 4       # Spoofable depending on receiver's implementation
VERDICT_ORG_MAILBOX = 5       # Org domain spoofing mailbox-dependent
VERDICT_BOTH_PARTIAL = 7      # Subdomain spoofable + org domain mailbox-dependent
VERDICT_NOT_SPOOFABLE = 8     # Not spoofable (strong protection)

SPOOFING_TYPES = {
    VERDICT_SPOOFABLE: "Spoofing possible for {domain}.",
    VERDICT_SUBDOMAIN_SPOOFABLE: "Subdomain spoofing possible for {domain}.",
    VERDICT_ORG_SPOOFABLE: "Organizational domain spoofing possible for {domain}.",
    VERDICT_MAYBE: "Spoofing might be possible for {domain}.",
    VERDICT_MAILBOX_DEP: "Spoofing might be possible (mailbox dependent) for {domain}.",
    VERDICT_ORG_MAILBOX: "Organizational domain spoofing might be possible (mailbox dependent) for {domain}.",
    VERDICT_BOTH_PARTIAL: "Subdomain spoofing is possible and organizational domain spoofing might be possible for {domain}.",
    VERDICT_NOT_SPOOFABLE: "Spoofing is not possible for {domain}.",
}

# Which verdicts mean "definitely spoofable"
DEFINITE_SPOOFABLE = {VERDICT_SPOOFABLE, VERDICT_SUBDOMAIN_SPOOFABLE, VERDICT_BOTH_PARTIAL}
# Which verdicts mean "definitely not spoofable"
DEFINITE_SAFE = {VERDICT_NOT_SPOOFABLE}


class Spoofing:
    def __init__(
        self,
        domain,
        dmarc_record,
        effective_p,
        aspf,
        spf_record,
        spf_all,
        spf_dns_queries,
        sp,
        pct,
    ):
        self.domain = domain
        self.dmarc_record = dmarc_record
        self.effective_p = effective_p
        # RFC 7489 §6.3: aspf defaults to "r" (relaxed) when absent
        self.aspf = aspf if aspf in ("r", "s") else "r"
        self.spf_record = spf_record
        self.spf_all = spf_all
        self.spf_dns_queries = spf_dns_queries
        # RFC 7489 §6.3: sp defaults to effective_p when absent
        self.sp = sp if sp else effective_p
        self.pct = self._safe_pct(pct)
        self.domain_type = self.get_domain_type()
        self.spoofable = self.is_spoofable()
        self.spoofing_possible, self.spoofing_type = self.evaluate_spoofing()

    @staticmethod
    def _safe_pct(pct):
        """Parse pct to int, defaulting to 100 on malformed input.

        Prevents ValueError from propagating into the exception handler
        (which invokes syntax.py and compounds the failure).
        """
        if pct is None:
            return 100
        try:
            val = int(pct)
            return max(0, min(val, 100))
        except (ValueError, TypeError):
            logger.debug("Malformed DMARC pct value: %r, treating as 100", pct)
            return 100

    def get_domain_type(self):
        """Determines whether the domain is a domain or subdomain."""
        subdomain = bool(tldextract.extract(self.domain).subdomain)
        return "subdomain" if subdomain else "domain"

    def is_spoofable(self):
        """Determine spoofability using a two-axis model.

        Axis 1 — Org-domain protection:
            - No DMARC + no SPF → fully spoofable (RFC 7489 §6.6.2)
            - DMARC p=reject/quarantine + SPF -all → protected
            - DMARC p=none → unprotected regardless of SPF (RFC 7489 §6.3)

        Axis 2 — Subdomain protection:
            - Uses sp (or p as fallback) with the same logic as axis 1

        Modifier — pct < 100:
            - RFC 7489 §6.6.4: only pct% of messages are subject to policy.
              This downgrades "not spoofable" to "might be spoofable".

        Returns:
            int: verdict code (0-8)
        """
        try:
            return self._evaluate()
        except Exception as e:
            logger.warning("Spoofing evaluation error for %s: %s", self.domain, e)
            return self._fallback_evaluate()

    def _evaluate(self):
        """Core spoofing evaluation logic."""
        has_spf = self.spf_record is not None
        has_dmarc = self.dmarc_record is not None

        # ── No records at all → fully spoofable ──────────────────────
        # RFC 7489 §6.6.2: without DMARC, receivers have no policy to apply
        if not has_spf and not has_dmarc:
            return VERDICT_SPOOFABLE

        # ── SPF exists but no DMARC → protection depends on receiver ─
        # Without DMARC, SPF alone doesn't protect the header-from
        if has_spf and not has_dmarc:
            if self.spf_all in ("-all", "~all"):
                # SPF provides envelope-from protection, but without DMARC
                # there's no policy tying SPF to the header-from
                return VERDICT_MAILBOX_DEP
            return VERDICT_SPOOFABLE

        # ── DMARC exists but no SPF ──────────────────────────────────
        if not has_spf and has_dmarc:
            if self.effective_p in ("reject", "quarantine"):
                # DMARC enforcement without SPF: alignment can't pass SPF,
                # so depends entirely on DKIM. Mailbox-dependent verdict.
                return VERDICT_MAILBOX_DEP
            return VERDICT_SPOOFABLE

        # ── SPF record is over the 10-lookup limit ───────────────────
        # RFC 7208 §4.6.4: exceeded limit → PermError → SPF fails
        if self.spf_dns_queries and self.spf_dns_queries > 10:
            if self.effective_p in ("reject", "quarantine"):
                # DMARC may still enforce via DKIM
                return VERDICT_MAYBE
            return VERDICT_SPOOFABLE

        # ── SPF has multiple 'all' mechanisms (misconfigured) ────────
        if self.spf_all == "2many":
            if self.effective_p in ("reject", "quarantine"):
                return VERDICT_NOT_SPOOFABLE
            return VERDICT_MAYBE

        # ── Both SPF and DMARC exist: evaluate two axes ──────────────

        org_protection = self._assess_org_domain()
        sub_protection = self._assess_subdomain()

        verdict = self._combine_axes(org_protection, sub_protection)

        # ── pct modifier ─────────────────────────────────────────────
        # RFC 7489 §6.6.4: only pct% of messages subject to policy.
        # A domain with pct < 100 cannot be "not spoofable" — some
        # fraction of spoofed messages will bypass enforcement.
        if self.pct < 100 and verdict == VERDICT_NOT_SPOOFABLE:
            return VERDICT_MAYBE

        return verdict

    def _assess_org_domain(self):
        """Assess org-domain (header-from) protection level.

        Returns: "protected", "soft", or "unprotected"

        Logic (RFC 7489 §6.3):
            - effective_p=reject/quarantine + strong SPF → protected
            - effective_p=reject/quarantine + weak SPF → soft (DKIM may help)
            - effective_p=none → unprotected (policy says "do nothing")
        """
        if self.effective_p in ("reject", "quarantine"):
            if self.spf_all == "-all":
                return "protected"
            elif self.spf_all in ("~all", "?all"):
                return "soft"
            else:
                # spf_all is +all or absent — SPF doesn't help,
                # but DMARC enforcement is still active via DKIM
                return "soft"
        # effective_p=none: receiver is told not to act on failures
        return "unprotected"

    def _assess_subdomain(self):
        """Assess subdomain protection level.

        Uses sp (already defaulted to p in __init__ if absent).
        Returns: "protected", "soft", or "unprotected"
        """
        if self.sp in ("reject", "quarantine"):
            if self.spf_all == "-all":
                return "protected"
            elif self.spf_all in ("~all", "?all"):
                return "soft"
            else:
                return "soft"
        return "unprotected"

    def _combine_axes(self, org, sub):
        """Combine org-domain and subdomain protection into a verdict.

        Matrix:
            org\\sub     | protected  | soft       | unprotected
            ------------|------------|------------|------------
            protected   | NOT_SPOOF  | NOT_SPOOF  | SUBDOMAIN
            soft        | ORG_MAILBOX| MAYBE      | BOTH_PARTIAL
            unprotected | ORG_SPOOF  | MAILBOX    | SPOOFABLE
        """
        if org == "protected":
            if sub in ("protected", "soft"):
                return VERDICT_NOT_SPOOFABLE
            return VERDICT_SUBDOMAIN_SPOOFABLE

        if org == "soft":
            if sub == "protected":
                return VERDICT_ORG_MAILBOX
            if sub == "soft":
                return VERDICT_MAYBE
            return VERDICT_BOTH_PARTIAL

        # org == "unprotected"
        if sub == "protected":
            return VERDICT_ORG_SPOOFABLE
        if sub == "soft":
            return VERDICT_MAILBOX_DEP
        return VERDICT_SPOOFABLE

    def _fallback_evaluate(self):
        """Fallback when primary evaluation throws.

        Uses syntax validators as a rough indicator: if both records
        are syntactically broken, assume fully spoofable.
        """
        spf_valid = False
        dmarc_valid = False

        if self.spf_record:
            spf_valid = validate_record_syntax(self.spf_record, "SPF")
        if self.dmarc_record:
            dmarc_valid = validate_record_syntax(self.dmarc_record, "DMARC")

        if not spf_valid and not dmarc_valid:
            return VERDICT_SPOOFABLE
        if dmarc_valid and self.effective_p in ("reject", "quarantine"):
            return VERDICT_NOT_SPOOFABLE
        if dmarc_valid and self.effective_p == "none":
            return VERDICT_MAYBE
        return VERDICT_MAILBOX_DEP

    def evaluate_spoofing(self):
        """Evaluates and returns whether spoofing is possible and the type."""
        spoofing_type = SPOOFING_TYPES.get(
            self.spoofable, "Unknown spoofing type for {domain}."
        ).format(domain=self.domain)

        if self.spoofable in DEFINITE_SPOOFABLE:
            spoofing_possible = True
        elif self.spoofable in DEFINITE_SAFE:
            spoofing_possible = False
        else:
            spoofing_possible = None  # "maybe"

        return spoofing_possible, spoofing_type

    def __str__(self):
        return (
            f"Domain: {self.domain}\n"
            f"Domain Type: {self.domain_type}\n"
            f"Spoofing Possible: {self.spoofing_possible}\n"
            f"Spoofing Type: {self.spoofing_type}"
        )
