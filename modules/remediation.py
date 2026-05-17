# modules/remediation.py

"""
Remediation advice engine for email security findings.

For every issue found, generates:
  - What's wrong (human-readable)
  - Why it matters (real-world impact)
  - Exact DNS record to fix it (copy-pasteable)
  - RFC / documentation reference
"""

from dataclasses import dataclass, field


@dataclass
class Recommendation:
    """A single remediation recommendation."""

    priority: int  # 1 = critical, 2 = high, 3 = medium, 4 = low, 5 = info
    category: str  # SPF, DMARC, DKIM, BIMI, GENERAL
    title: str
    description: str
    impact: str
    fix: str  # Copy-pasteable DNS record or action
    reference: str  # RFC or documentation URL
    eli5_explanation: str = ""
    business_risk: str = ""

    PRIORITY_LABELS = {
        1: "🔴 CRITICAL",
        2: "🟠 HIGH",
        3: "🟡 MEDIUM",
        4: "🔵 LOW",
        5: "ℹ️  INFO",
    }

    @property
    def priority_label(self):
        return self.PRIORITY_LABELS.get(self.priority, "UNKNOWN")

    def to_dict(self):
        return {
            "priority": self.priority,
            "priority_label": self.priority_label,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "fix": self.fix,
            "reference": self.reference,
            "eli5_explanation": self.eli5_explanation,
            "business_risk": self.business_risk,
        }


class RemediationEngine:
    """Generates remediation recommendations based on scan results."""

    def __init__(self, result):
        """
        Initialize with a result dict from process_domain().

        Args:
            result: dict with keys like SPF, DMARC, DKIM, BIMI_RECORD, etc.
        """
        self.result = result
        self.domain = result.get("DOMAIN", "example.com")
        self.mx_providers = result.get("MX_PROVIDERS", [])
        self.recommendations = self._generate_recommendations()

    def _generate_recommendations(self):
        """Run all checks and return sorted recommendations."""
        recs = []
        recs.extend(self._check_spf())
        recs.extend(self._check_dmarc())
        recs.extend(self._check_dkim())
        recs.extend(self._check_bimi())
        recs.extend(self._check_spoofability())
        recs.extend(self._check_mta_sts())
        recs.extend(self._check_mx())
        recs.extend(self._check_caa())
        recs.extend(self._check_dnssec())
        recs.extend(self._check_dane())
        # Sort by priority (critical first)
        recs.sort(key=lambda r: r.priority)
        return recs

    def _normalize_spf_all(self, spf_record, old_all, new_all):
        """Replace an 'all' mechanism in an SPF record, handling bare 'all'.

        Per RFC 7208, bare 'all' is implicitly '+all'. If the raw record
        contains bare 'all' (no qualifier), normalize it before replacing.
        """
        if not spf_record:
            return spf_record
        # Tokenize, normalize bare 'all' to '+all', then replace
        tokens = spf_record.split()
        normalized = []
        for token in tokens:
            if token == "all":
                normalized.append("+all")
            else:
                normalized.append(token)
        result = " ".join(normalized)
        return result.replace(old_all, new_all)

    # --- SPF Checks ---

    def _check_spf(self):
        recs = []
        spf = self.result.get("SPF")
        spf_all = self.result.get("SPF_ALL")
        too_many = self.result.get("SPF_TOO_MANY_DNS_QUERIES", False)
        query_count = self.result.get("SPF_DNS_QUERY_COUNT", 0)

        if not spf:
            recs.append(
                Recommendation(
                    priority=1,
                    category="SPF",
                    title="No SPF record found",
                    description=(
                        f"The domain {self.domain} has no SPF (Sender Policy Framework) record. "
                        "Without SPF, any mail server can send emails pretending to be from your domain."
                    ),
                    impact=(
                        "Attackers can send phishing emails that appear to come from your domain. "
                        "Receiving mail servers have no way to verify the sender's legitimacy."
                    ),
                    fix=(
                        f'{self.domain}.  IN  TXT  "v=spf1 include:_spf.google.com -all"\n\n'
                        "Replace 'include:_spf.google.com' with your actual email provider's SPF include. "
                        "Common includes:\n"
                        "  • Microsoft 365:  include:spf.protection.outlook.com\n"
                        "  • Google Workspace: include:_spf.google.com\n"
                        "  • Proofpoint:     include:spf.proofpoint.com"
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208",
                    eli5_explanation="SPF is like a guest list for a party. Right now, you have no list, so the bouncer lets anyone in claiming to be you.",
                    business_risk="Attackers can perfectly impersonate your CEO and ask finance to wire money to a fraudulent account.",
                )
            )
            return recs

        # RFC 7208 §4.5: Multiple SPF records = PermError
        permerror = self.result.get("SPF_PERMERROR", False)
        if permerror:
            recs.append(
                Recommendation(
                    priority=1,
                    category="SPF",
                    title="Multiple SPF records cause PermError",
                    description=(
                        f"The domain {self.domain} has more than one TXT record beginning with "
                        "'v=spf1'. Per RFC 7208 §4.5, receiving MTAs MUST abort the SPF check "
                        "and return a PermError when multiple SPF records are found."
                    ),
                    impact=(
                        "Your domain's SPF provides ZERO protection. All receiving MTAs will "
                        "abort the SPF evaluation before reading any of the records. This is "
                        "functionally worse than having no SPF record at all."
                    ),
                    fix=(
                        "Consolidate all SPF directives into a single TXT record. "
                        "Only one record beginning with 'v=spf1' may exist per domain.\n\n"
                        "If you have multiple email providers, combine them with 'include:' "
                        "directives in a single record:\n\n"
                        f'{self.domain}.  IN  TXT  "v=spf1 include:provider1 include:provider2 -all"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-4.5",
                    eli5_explanation=(
                        "Imagine two bouncers at your party with different guest lists. "
                        "They start arguing and give up — everyone gets turned away."
                    ),
                    business_risk=(
                        "All legitimate email from your domain may be rejected or marked as spam "
                        "by receiving mail servers."
                    ),
                )
            )
            return recs

        if spf_all == "+all":
            recs.append(
                Recommendation(
                    priority=1,
                    category="SPF",
                    title='SPF uses "+all" — allows anyone to send',
                    description=(
                        f"The SPF record for {self.domain} ends with '+all', which explicitly "
                        "permits ALL mail servers to send email on behalf of your domain."
                    ),
                    impact=(
                        "This is equivalent to having no SPF at all. Any attacker can spoof "
                        "your domain with full SPF pass results."
                    ),
                    fix=(
                        "Change '+all' to '-all' in your SPF record:\n\n"
                        f'{self.domain}.  IN  TXT  "{self._normalize_spf_all(spf, "+all", "-all")}"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                    eli5_explanation="You actually put '+all' on your guest list, which literally translates to 'everyone is invited'. Anybody can send mail as you.",
                    business_risk="Extreme impersonation risk. Scammers will use your domain to send spam and phishing emails, ruining your reputation.",
                )
            )

        elif spf_all == "?all":
            recs.append(
                Recommendation(
                    priority=2,
                    category="SPF",
                    title='SPF uses "?all" — neutral policy provides no protection',
                    description=(
                        f"The SPF record for {self.domain} ends with '?all' (neutral), which "
                        "means the SPF result is treated as if no SPF record exists."
                    ),
                    impact=(
                        "Receiving mail servers will not reject or flag emails from unauthorized "
                        "senders. Spoofing is still easily possible."
                    ),
                    fix=(
                        "Change '?all' to '-all' (or '~all' as an intermediate step):\n\n"
                        f'{self.domain}.  IN  TXT  "{self._normalize_spf_all(spf, "?all", "-all")}"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                )
            )

        elif spf_all == "~all":
            dmarc_policy = self.result.get("DMARC_EFFECTIVE_POLICY")
            if dmarc_policy in ("quarantine", "reject"):
                # With DMARC enforcement, ~all vs -all has minimal practical impact
                # because DMARC alignment already drives the enforcement decision.
                description = (
                    f"The SPF record for {self.domain} uses softfail (~all). At the SPF layer "
                    "this doesn't instruct receivers to reject unauthorized senders. However, "
                    f"your DMARC policy is '{dmarc_policy}', which already enforces action on "
                    "alignment failures regardless of the SPF qualifier. The practical delta "
                    "between ~all and -all is therefore minimal for your domain."
                )
                impact = (
                    "With DMARC at '{0}', the difference between ~all and -all is primarily "
                    "cosmetic in DMARC aggregate reports and minor receiver heuristics. "
                    "Upgrading to -all is still best practice for clarity and defense in depth."
                ).format(dmarc_policy)
            else:
                description = (
                    f"The SPF record for {self.domain} uses softfail (~all). While this marks "
                    "unauthorized senders, it doesn't instruct receivers to reject them."
                )
                impact = (
                    "Most modern mail providers treat ~all similarly to -all, but the strongest "
                    "protection comes from an explicit hard fail."
                )
            recs.append(
                Recommendation(
                    priority=4,
                    category="SPF",
                    title='SPF uses "~all" — consider upgrading to "-all"',
                    description=description,
                    impact=impact,
                    fix=(
                        "When you're confident your SPF includes are complete, change '~all' to '-all':\n\n"
                        f'{self.domain}.  IN  TXT  "{self._normalize_spf_all(spf, "~all", "-all")}"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                )
            )

        if spf_all == "2many":
            recs.append(
                Recommendation(
                    priority=2,
                    category="SPF",
                    title="SPF record contains multiple 'all' mechanisms",
                    description=(
                        f"The SPF record for {self.domain} has more than one 'all' mechanism. "
                        "Only the first 'all' mechanism should be present and it should be the last term."
                    ),
                    impact=(
                        "Multiple 'all' mechanisms indicate a misconfiguration that may cause "
                        "unpredictable SPF evaluation results."
                    ),
                    fix=(
                        "Remove all but the last 'all' mechanism from your SPF record. "
                        "Ensure a single '-all' appears at the end."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                )
            )

        if spf_all is None and spf:
            recs.append(
                Recommendation(
                    priority=3,
                    category="SPF",
                    title="SPF record has no 'all' mechanism",
                    description=(
                        f"The SPF record for {self.domain} doesn't include an 'all' mechanism. "
                        "Without it, the default result for non-matching senders is neutral."
                    ),
                    impact=(
                        "Emails from unauthorized servers will get a neutral SPF result, "
                        "providing no real protection."
                    ),
                    fix=(
                        f"Add '-all' at the end of your SPF record:\n\n"
                        f'{self.domain}.  IN  TXT  "{spf} -all"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                )
            )

        if too_many:
            recs.append(
                Recommendation(
                    priority=2,
                    category="SPF",
                    title=f"SPF exceeds 10 DNS lookup limit ({query_count} lookups)",
                    description=(
                        f"The SPF record for {self.domain} requires {query_count} DNS lookups, "
                        "exceeding the RFC-mandated limit of 10."
                    ),
                    impact=(
                        "Receiving mail servers will return a PermError for SPF, which can "
                        "cause emails to be rejected or treated as suspicious."
                    ),
                    fix=(
                        "Reduce DNS lookups by:\n"
                        "  1. Replacing 'include:' with 'ip4:'/'ip6:' for known static IPs\n"
                        "  2. Removing unused includes\n"
                        "  3. Using an SPF flattening service\n"
                        f"  Current count: {query_count} (max allowed: 10)"
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4",
                    eli5_explanation="Your guest list is a list of other lists (vendors like Mailchimp). Mail servers like Gmail refuse to check more than 10 lists to verify a sender. You're over the limit.",
                    business_risk="Legitimate emails from your actual employees and marketing tools may go straight to the recipient's spam folder entirely because of this technical error.",
                )
            )

        return recs

    # --- DMARC Checks ---

    def _check_dmarc(self):
        recs = []
        dmarc = self.result.get("DMARC")
        policy = self.result.get("DMARC_EFFECTIVE_POLICY")
        is_org_fallback = self.result.get("DMARC_ORG_DOMAIN_FALLBACK", False)
        pct = self.result.get("DMARC_PCT")
        rua = self.result.get("DMARC_AGGREGATE_REPORT")
        fo = self.result.get("DMARC_FORENSIC_REPORT")
        aspf = self.result.get("DMARC_ASPF")
        sp = self.result.get("DMARC_SP")

        if not dmarc:
            recs.append(
                Recommendation(
                    priority=1,
                    category="DMARC",
                    title="No DMARC record found",
                    description=(
                        f"The domain {self.domain} has no DMARC (Domain-based Message Authentication, "
                        "Reporting and Conformance) record."
                    ),
                    impact=(
                        "Without DMARC, there is no policy telling receiving mail servers what to do "
                        "with emails that fail SPF/DKIM checks. Spoofed emails will likely be delivered."
                    ),
                    fix=(
                        "Add a DMARC record. Start with monitoring mode, then tighten:\n\n"
                        "Step 1 — Monitor:\n"
                        f'_dmarc.{self.domain}.  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@{self.domain}; pct=100"\n\n'
                        "Step 2 — After reviewing reports, quarantine:\n"
                        f'_dmarc.{self.domain}.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{self.domain}; pct=100"\n\n'
                        "Step 3 — Full enforcement:\n"
                        f'_dmarc.{self.domain}.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{self.domain}; pct=100"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489",
                    eli5_explanation="DMARC is the instructions you give to receiving mail servers on what to do when someone fakes your email. Without it, they guess, and they usually guess wrong.",
                    business_risk="Without a DMARC policy, spoofed emails from your domain will directly land in your customers' inboxes.",
                )
            )
            return recs

        # Build context-aware fix prefix for inherited policies
        if is_org_fallback:
            policy_source = (
                f"Note: {self.domain} does not have its own DMARC record — this policy "
                f"is inherited from the organizational domain. To change it, either:\n"
                f"  (a) Publish a DMARC record at _dmarc.{self.domain} with a stronger policy, or\n"
                f"  (b) Strengthen the org domain's p= or sp= tag.\n\n"
            )
        else:
            policy_source = ""

        if policy == "none":
            recs.append(
                Recommendation(
                    priority=2,
                    category="DMARC",
                    title='DMARC policy is "none" — no enforcement',
                    description=(
                        f"The effective DMARC policy for {self.domain} is 'none', which means "
                        "emails failing authentication are still delivered normally."
                    ),
                    impact=(
                        "The 'none' policy is useful for monitoring, but does not protect "
                        "against spoofing. Attackers can still send emails as your domain."
                    ),
                    fix=(
                        f"{policy_source}"
                        "Upgrade to 'quarantine' or 'reject' after reviewing DMARC reports:\n\n"
                        f'_dmarc.{self.domain}.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{self.domain}; pct=100"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                    eli5_explanation="p=none is essentially saying: 'Please check if this email is fake. If it is fake... do nothing, let it through anyway.'",
                    business_risk="Your brand is highly exposed to phishing attacks targeting your customers, as your policy 'none' does not ask providers to block bad actors.",
                )
            )

        elif policy == "quarantine":
            recs.append(
                Recommendation(
                    priority=4,
                    category="DMARC",
                    title='DMARC policy is "quarantine" — consider upgrading to "reject"',
                    description=(
                        f"The effective DMARC policy for {self.domain} is 'quarantine'. "
                        "Failing emails are sent to spam/junk rather than rejected outright."
                    ),
                    impact=(
                        "Quarantine is good protection, but users may still see spoofed "
                        "emails in their spam folder. Reject is the strongest setting."
                    ),
                    fix=(
                        f"{policy_source}"
                        f'_dmarc.{self.domain}.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{self.domain}; pct=100"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                )
            )

        if pct is not None and str(pct).strip() != "100":
            recs.append(
                Recommendation(
                    priority=3,
                    category="DMARC",
                    title=f"DMARC pct={pct}% — policy not applied to all messages",
                    description=(
                        f"Only {pct}% of messages are subject to the DMARC policy for {self.domain}. "
                        "The remaining messages bypass policy enforcement."
                    ),
                    impact=(
                        f"{100 - int(pct) if pct else 'Unknown'}% of spoofed emails will NOT be "
                        "subject to your DMARC policy."
                    ),
                    fix=(
                        f"Increase pct to 100 when you're confident in your configuration:\n\n"
                        f"Change 'pct={pct}' to 'pct=100' in your DMARC record."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                )
            )

        if not rua:
            recs.append(
                Recommendation(
                    priority=3,
                    category="DMARC",
                    title="No DMARC aggregate reporting (rua) configured",
                    description=(
                        f"The DMARC record for {self.domain} does not specify an aggregate report "
                        "destination (rua tag)."
                    ),
                    impact=(
                        "Without reports, you have zero visibility into who is sending email "
                        "on behalf of your domain — legitimate or malicious."
                    ),
                    fix=(
                        f"Add 'rua=mailto:dmarc-reports@{self.domain}' to your DMARC record.\n\n"
                        "You can also use a free DMARC report analyzer service like:\n"
                        "  • https://dmarc.postmarkapp.com\n"
                        "  • https://www.dmarcanalyzer.com"
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.2",
                )
            )

        if sp is None and dmarc:
            recs.append(
                Recommendation(
                    priority=4,
                    category="DMARC",
                    title="No subdomain policy (sp=) specified",
                    description=(
                        f"The DMARC record for {self.domain} does not set a subdomain policy (sp=). "
                        "Subdomains inherit the main domain's policy by default."
                    ),
                    impact=(
                        "If your main policy is 'reject' but you have unmonitored subdomains, "
                        "they're covered. But explicitly setting sp= makes your intent clear "
                        "and protects against configuration drift."
                    ),
                    fix=(
                        f"Add 'sp=reject' to your DMARC record to explicitly enforce on subdomains."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                )
            )

        if sp == "none" and policy in ("quarantine", "reject"):
            recs.append(
                Recommendation(
                    priority=3,
                    category="DMARC",
                    title="Subdomain policy weaker than domain policy",
                    description=(
                        f"The main domain {self.domain} has p={policy}, but subdomains have sp=none. "
                        "This creates a gap attackers can exploit."
                    ),
                    impact=(
                        f"Attackers can spoof subdomains (e.g., mail.{self.domain}, support.{self.domain}) "
                        "because the subdomain policy allows it."
                    ),
                    fix=(
                        f"Change 'sp=none' to 'sp={policy}' in your DMARC record."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                )
            )

        return recs

    # --- DKIM Checks ---

    def _check_dkim(self):
        recs = []
        dkim = self.result.get("DKIM")
        selectors = self.result.get("DKIM_SELECTORS", [])
        has_weak = self.result.get("DKIM_HAS_WEAK_KEYS", False)
        dkim_scanned = self.result.get("DKIM_SCANNED", True)

        if not dkim_scanned:
            # DKIM was not scanned — don't advise to configure something we didn't check
            return recs

        if not dkim:
            recs.append(
                Recommendation(
                    priority=3,
                    category="DKIM",
                    title="No DKIM selectors found",
                    description=(
                        f"No DKIM (DomainKeys Identified Mail) selectors were found for {self.domain}. "
                        "Both API lookup and DNS brute-forcing of common selectors returned no results."
                    ),
                    impact=(
                        "Without DKIM, emails lack cryptographic signatures. DMARC alignment "
                        "can only rely on SPF, reducing overall email authentication strength."
                    ),
                    fix=(
                        "Configure DKIM signing on your email provider:\n\n"
                        "  • Microsoft 365: Microsoft 365 Defender Admin Center -> Email & Collaboration -> Policies & Rules -> Threat policies -> Email authentication settings -> DKIM -> Create DKIM keys\n"
                        "  • Google Workspace: Admin Console -> Apps -> Google Workspace -> Gmail -> Authenticate email -> Generate New Record\n"
                        "  • Custom: Generate a 2048-bit RSA key pair and publish the public key:\n"
                        f'    selector._domainkey.{self.domain}.  IN  TXT  "v=DKIM1; k=rsa; p=<public_key>"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc6376",
                    eli5_explanation="DKIM is a wax seal on your emails proving nobody tampered with them in transit. You have no wax seal.",
                    business_risk="Without DKIM, forwarded emails or emails sent through third parties will fail DMARC alignment, dropping your legitimate email delivery rates.",
                )
            )

        # Check individual selectors for issues
        if selectors:
            for sel in selectors:
                bits = sel.get("key_bits")
                selector_name = sel.get("selector", "unknown")

                # Revoked keys (RFC 6376 §3.6.1 — empty p= tag)
                if sel.get("is_revoked"):
                    recs.append(
                        Recommendation(
                            priority=4,
                            category="DKIM",
                            title=f"DKIM key '{selector_name}' is revoked",
                            description=(
                                f"The DKIM selector '{selector_name}' for {self.domain} has an empty p= tag, "
                                "which per RFC 6376 §3.6.1 means the key has been revoked. "
                                "All signatures using this selector will fail verification."
                            ),
                            impact=(
                                "A revoked key is expected when rotating keys. If this is intentional, "
                                "the selector can be removed from DNS after the transition period. "
                                "If unintentional, emails signed with this key are failing DKIM checks."
                            ),
                            fix=(
                                f"If key rotation is complete, remove the DNS record:\n\n"
                                f"  DELETE  {selector_name}._domainkey.{self.domain}  TXT\n\n"
                                f"If this was unintentional, re-publish the public key."
                            ),
                            reference="https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1",
                        )
                    )
                    continue

                # Testing mode (RFC 6376 §3.6.1 — t=y flag)
                if sel.get("is_testing"):
                    recs.append(
                        Recommendation(
                            priority=2,
                            category="DKIM",
                            title=f"DKIM key '{selector_name}' is in testing mode (t=y)",
                            description=(
                                f"The DKIM selector '{selector_name}' for {self.domain} has the t=y flag set. "
                                "Per RFC 6376 §3.6.1, verifiers MUST NOT treat testing-mode signatures "
                                "differently from unsigned email — meaning DKIM provides no protection."
                            ),
                            impact=(
                                "While the t=y flag is set, DKIM signatures from this selector offer "
                                "no security benefit. DMARC alignment via DKIM is effectively disabled."
                            ),
                            fix=(
                                f"Remove the 'y' flag from the t= tag in the DNS record:\n\n"
                                f'  {selector_name}._domainkey.{self.domain}.  IN  TXT  "v=DKIM1; k=rsa; p=<key>"\n\n'
                                "Remove the t=y flag only after confirming DKIM signing is working correctly."
                            ),
                            reference="https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1",
                        )
                    )

                # Weak keys (algorithm-aware — uses dkim.py's is_weak flag)
                if sel.get("is_weak"):
                    algo = sel.get("algorithm", "rsa")
                    recs.append(
                        Recommendation(
                            priority=2,
                            category="DKIM",
                            title=f"DKIM key '{selector_name}' is only {bits}-bit {algo.upper()} (weak)",
                            description=(
                                f"The DKIM selector '{selector_name}' for {self.domain} uses a "
                                f"{bits}-bit {algo.upper()} key. "
                                + ("Keys shorter than 2048 bits are considered weak "
                                   "and may be factored by determined attackers."
                                   if algo == "rsa" else
                                   f"This {algo} key length is below the recommended minimum.")
                            ),
                            impact=(
                                "A weak DKIM key could be broken, allowing attackers to forge "
                                "DKIM signatures and bypass DMARC authentication."
                            ),
                            fix=(
                                f"Generate a new 2048-bit (or 4096-bit) RSA key for selector '{selector_name}':\n\n"
                                f'    {selector_name}._domainkey.{self.domain}.  IN  TXT  "v=DKIM1; k=rsa; p=<new_2048bit_key>"\n\n'
                                "Then update your email server to sign with the new key."
                            ),
                            reference="https://datatracker.ietf.org/doc/html/rfc8301",
                        )
                    )

                # SHA-1 only (RFC 6376 §3.3 — rsa-sha256 SHOULD be used)
                if sel.get("is_sha1_only"):
                    recs.append(
                        Recommendation(
                            priority=3,
                            category="DKIM",
                            title=f"DKIM key '{selector_name}' restricted to SHA-1 only",
                            description=(
                                f"The DKIM selector '{selector_name}' for {self.domain} has h=sha1, "
                                "restricting it to SHA-1 hash algorithm only. Per RFC 6376 §3.3, "
                                "signers SHOULD sign using rsa-sha256."
                            ),
                            impact=(
                                "SHA-1 is cryptographically weaker than SHA-256. While still accepted "
                                "by most verifiers, some may downgrade trust for SHA-1-only signatures."
                            ),
                            fix=(
                                f"Update the key record to allow SHA-256:\n\n"
                                f'  {selector_name}._domainkey.{self.domain}.  IN  TXT  "v=DKIM1; k=rsa; h=sha256; p=<key>"\n\n'
                                "Or remove the h= tag entirely to allow all algorithms (default)."
                            ),
                            reference="https://datatracker.ietf.org/doc/html/rfc6376#section-3.3",
                        )
                    )

        return recs

    # --- BIMI Checks ---

    def _check_bimi(self):
        recs = []
        bimi = self.result.get("BIMI_RECORD")
        dmarc_policy = self.result.get("DMARC_POLICY")

        if not bimi:
            # BIMI is optional, so this is low priority
            if dmarc_policy in ("quarantine", "reject"):
                if dmarc_policy == "quarantine":
                    dmarc_context = (
                        f"The domain {self.domain} has DMARC at quarantine, which meets the minimum "
                        "BIMI requirement, though Gmail prioritizes p=reject for logo display. "
                        "BIMI allows your brand logo to appear next to your emails in supporting clients."
                    )
                else:
                    dmarc_context = (
                        f"The domain {self.domain} has DMARC at reject, which is the optimal "
                        "DMARC policy for BIMI. "
                        "BIMI allows your brand logo to appear next to your emails in supporting clients."
                    )
                recs.append(
                    Recommendation(
                        priority=5,
                        category="BIMI",
                        title="Consider adding a BIMI record for brand visibility",
                        description=dmarc_context,
                        impact=(
                            "BIMI increases brand recognition and builds trust with recipients. "
                            "It's also a signal that your email authentication is mature."
                        ),
                        fix=(
                            f'default._bimi.{self.domain}.  IN  TXT  "v=BIMI1; l=https://{self.domain}/brand/logo.svg"\n\n'
                            "Requirements:\n"
                            "  • Logo must be in SVG Tiny Portable/Secure format\n"
                            "  • DMARC policy must be quarantine or reject\n"
                            "  • A Verified Mark Certificate (VMC) is REQUIRED for Gmail to display your logo\n"
                            "    (Apple Mail displays without VMC). VMCs are issued by DigiCert and Entrust,\n"
                            "    typically costing €1,000-2,000/year, and require a registered trademark."
                        ),
                        reference="https://datatracker.ietf.org/doc/html/draft-brand-indicators-for-message-identification",
                    )
                )

        return recs

    # --- Spoofability Checks ---

    def _check_spoofability(self):
        recs = []
        spoofable = self.result.get("SPOOFING_POSSIBLE")
        spoof_type = self.result.get("SPOOFING_TYPE", "")

        if spoofable is True:
            recs.append(
                Recommendation(
                    priority=1,
                    category="GENERAL",
                    title="Domain is vulnerable to email spoofing",
                    description=(
                        f"Based on the SPF and DMARC configuration, {self.domain} can be spoofed. "
                        f"Details: {spoof_type}"
                    ),
                    impact=(
                        "Attackers can send convincing phishing emails appearing to come from "
                        "your domain. This can lead to credential theft, malware delivery, "
                        "and reputational damage."
                    ),
                    fix="See the SPF and DMARC recommendations above to fix the underlying issues.",
                    reference="https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security",
                )
            )
        elif spoofable is None:
            recs.append(
                Recommendation(
                    priority=3,
                    category="GENERAL",
                    title="Spoofing may be possible (mailbox dependent)",
                    description=(
                        f"The email configuration for {self.domain} has gaps that may allow "
                        f"spoofing depending on the receiving mail server. Details: {spoof_type}"
                    ),
                    impact=(
                        "Some email providers may deliver spoofed emails while others won't. "
                        "This inconsistency is a risk."
                    ),
                    fix="See the SPF and DMARC recommendations above to strengthen your configuration.",
                    reference="https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security",
                )
            )

        return recs

    # --- MTA-STS & TLS-RPT Checks ---

    def _check_mta_sts(self):
        recs = []

        # Null MX (RFC 7505): domain intentionally receives no email.
        # MTA-STS and TLS-RPT are inapplicable — skip all recommendations.
        if self.result.get("MX_HAS_NULL_MX", False):
            return recs

        mta_sts_txt = self.result.get("MTA_STS_TXT")
        mta_sts_mode = self.result.get("MTA_STS_MODE")
        max_age = self.result.get("MTA_STS_MAX_AGE")
        tls_rpt = self.result.get("TLS_RPT_RECORD")

        # ---- 1. MTA-STS Evaluation ----
        if self.result.get("MTA_STS_PERMERROR"):
            recs.append(
                Recommendation(
                    priority=1,
                    category="MTA-STS",
                    title="Multiple MTA-STS TXT records found (PermError)",
                    description=(
                        f"The domain {self.domain} has published more than one "
                        "_mta-sts TXT record starting with 'v=STSv1'."
                    ),
                    impact=(
                        "Per RFC 8461 §3.1, senders MUST assume the domain does "
                        "not have an available MTA-STS policy. Your MTA-STS "
                        "deployment is functionally disabled."
                    ),
                    fix=(
                        "Consolidate your MTA-STS TXT records into a single "
                        "record starting with 'v=STSv1;'."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc8461#section-3.1",
                )
            )
        elif not mta_sts_txt:
            # Build MX lines from detected MX records for copy-pasteable fix
            mx_records = self.result.get("MX_RECORDS", [])
            if mx_records:
                mx_lines = []
                for mx in mx_records:
                    host = mx.get("host", "")
                    if host and not mx.get("is_null_mx"):
                        # Use wildcard prefix for managed providers (e.g. *.mail.protection.outlook.com)
                        parts = host.split(".", 1)
                        if len(parts) > 1:
                            mx_lines.append(f"   mx: *.{parts[1]}")
                        else:
                            mx_lines.append(f"   mx: {host}")
                if not mx_lines:
                    mx_lines = ["   mx: *.your-mx-host.com"]
                mx_block = "\n".join(mx_lines)
            else:
                mx_block = "   mx: *.your-mx-host.com"

            recs.append(
                Recommendation(
                    priority=4,
                    category="MTA-STS",
                    title="No MTA-STS policy configured",
                    description=(
                        f"The domain {self.domain} has no MTA-STS (SMTP MTA Strict Transport Security) "
                        "policy. MTA-STS instructs MTA-STS-aware senders (Gmail, Microsoft 365, "
                        "and other large providers) to enforce TLS-encrypted delivery to your domain."
                    ),
                    impact=(
                        "Without MTA-STS, SMTP connections to your mail servers can be downgraded "
                        "to unencrypted plaintext via man-in-the-middle attacks. Note that MTA-STS "
                        "only protects against downgrade from senders that implement the standard."
                    ),
                    fix=(
                        "1. Publish a TXT record (increment the id value on every policy change):\n"
                        f'   _mta-sts.{self.domain}.  IN  TXT  "v=STSv1; id=YYYYMMDD01"\n\n'
                        "2. Host a policy file at https://mta-sts." + self.domain + "/.well-known/mta-sts.txt:\n"
                        "   version: STSv1\n"
                        "   mode: testing\n"
                        f"{mx_block}\n"
                        "   max_age: 86400\n\n"
                        "3. After validating that TLS-RPT reports show no failures, change mode to 'enforce'."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc8461",
                )
            )
        else:
            # TXT record exists — evaluate the HTTPS policy
            if mta_sts_mode == "enforce":
                pass  # Optimal configuration
            elif mta_sts_mode == "testing":
                recs.append(
                    Recommendation(
                        priority=4,
                        category="MTA-STS",
                        title="MTA-STS is in testing mode — not enforced",
                        description=(
                            f"MTA-STS for {self.domain} is set to 'testing' mode. This reports "
                            "TLS failures but does not enforce encrypted delivery."
                        ),
                        impact=(
                            "SMTP connections can still be downgraded. Testing mode is for "
                            "validation only and should be upgraded to enforce."
                        ),
                        fix="Change 'mode: testing' to 'mode: enforce' in your MTA-STS policy file.",
                        reference="https://datatracker.ietf.org/doc/html/rfc8461#section-5",
                    )
                )
            elif mta_sts_mode == "none":
                recs.append(
                    Recommendation(
                        priority=3,
                        category="MTA-STS",
                        title="MTA-STS mode is 'none' — no protection",
                        description=(
                            f"MTA-STS for {self.domain} has mode=none, effectively disabling "
                            "transport security enforcement."
                        ),
                        impact="SMTP downgrade attacks are fully possible.",
                        fix="Change 'mode: none' to 'mode: enforce' in your MTA-STS policy file.",
                        reference="https://datatracker.ietf.org/doc/html/rfc8461#section-5",
                    )
                )
            elif not mta_sts_mode:
                # TXT record exists but HTTPS policy is unreachable, timed out,
                # or contains syntax errors (e.g. missing 'version: STSv1').
                recs.append(
                    Recommendation(
                        priority=1,
                        category="MTA-STS",
                        title="MTA-STS policy file is missing, invalid, or unreachable",
                        description=(
                            f"The domain {self.domain} has a valid MTA-STS TXT record, but "
                            f"the policy file at https://mta-sts.{self.domain}/.well-known/mta-sts.txt "
                            "could not be fetched or contained syntax errors."
                        ),
                        impact=(
                            "Receiving MTAs will see the TXT record but fail to load the policy. "
                            "This represents a broken deployment. MTAs will fall back to plaintext "
                            "or delay mail depending on their cache state."
                        ),
                        fix=(
                            "Ensure a valid policy file is hosted at the exact HTTPS URL, served "
                            "with Content-Type 'text/plain', and contains at minimum 'version: STSv1', "
                            "'mode', 'max_age', and 'mx' keys."
                        ),
                        reference="https://datatracker.ietf.org/doc/html/rfc8461#section-3.3",
                    )
                )

            if max_age and isinstance(max_age, int) and max_age < 86400:
                recs.append(
                    Recommendation(
                        priority=5,
                        category="MTA-STS",
                        title=f"MTA-STS max_age is short ({max_age}s)",
                        description=(
                            f"The MTA-STS policy max_age for {self.domain} is {max_age} seconds "
                            f"({max_age // 3600}h). A longer max_age provides better cache protection."
                        ),
                        impact="Sending servers re-fetch the policy more frequently, increasing exposure windows.",
                        fix="Set max_age to at least 86400 (1 day), ideally 604800 (1 week) or more.",
                        reference="https://datatracker.ietf.org/doc/html/rfc8461#section-3.1",
                    )
                )

        # ---- 2. TLS-RPT Evaluation (independent of MTA-STS) ----
        if self.result.get("TLS_RPT_PERMERROR"):
            recs.append(
                Recommendation(
                    priority=2,
                    category="TLS-RPT",
                    title="Multiple TLS-RPT TXT records found (PermError)",
                    description=(
                        f"The domain {self.domain} has published more than one "
                        "_smtp._tls TXT record starting with 'v=TLSRPTv1'."
                    ),
                    impact=(
                        "Per RFC 8460 §3, senders MUST assume the domain does "
                        "not have a reporting policy."
                    ),
                    fix=(
                        "Consolidate your TLS-RPT TXT records into a single "
                        "record starting with 'v=TLSRPTv1;'."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc8460#section-3",
                )
            )
        elif not tls_rpt:
            recs.append(
                Recommendation(
                    priority=4,
                    category="TLS-RPT",
                    title="No TLS-RPT reporting configured",
                    description=(
                        f"The domain {self.domain} has no TLS-RPT (SMTP TLS Reporting) record. "
                        "TLS-RPT provides visibility into TLS negotiation failures."
                    ),
                    impact=(
                        "Without TLS-RPT, you won't know if sending servers are failing to "
                        "establish secure connections with your mail infrastructure."
                    ),
                    fix=(
                        f'_smtp._tls.{self.domain}.  IN  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@{self.domain}"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc8460",
                )
            )

        return recs

    # --- MX Infrastructure Checks ---

    def _check_mx(self):
        recs = []
        mx_records = self.result.get("MX_RECORDS", [])
        mx_count = self.result.get("MX_COUNT", 0)
        all_starttls = self.result.get("MX_ALL_STARTTLS")
        all_ptr = self.result.get("MX_ALL_PTR")

        if mx_count == 0:
            recs.append(
                Recommendation(
                    priority=3,
                    category="MX",
                    title="No MX records found",
                    description=(
                        f"No MX (Mail Exchanger) records were found for {self.domain}. "
                        "Without MX records, email delivery may fall back to A record resolution."
                    ),
                    impact="Email delivery reliability is significantly reduced.",
                    fix=f'{self.domain}.  IN  MX  10 mail.{self.domain}.',
                    reference="https://datatracker.ietf.org/doc/html/rfc5321#section-5",
                )
            )
            return recs

        # Null MX (RFC 7505) is intentional — no inbound mail. Skip redundancy advice.
        if self.result.get("MX_HAS_NULL_MX"):
            return recs

        if mx_count == 1:
            # Check if the single MX points to a managed provider with built-in
            # geo-redundancy. For these providers, adding a secondary MX is
            # incorrect — it would bypass spam/malware filtering or create
            # routing ambiguity that breaks delivery.
            managed_providers = {
                "Microsoft 365", "Microsoft 365 (GCC)", "Microsoft 365 (GCC High)",
                "Google Workspace", "Mimecast", "Proofpoint", "Proofpoint Essentials",
                "Barracuda", "Cisco Secure Email", "Sophos", "Trend Micro",
            }
            mx_providers = set(self.result.get("MX_PROVIDERS", []))
            is_managed = bool(mx_providers & managed_providers)

            if is_managed:
                provider_name = ", ".join(mx_providers & managed_providers)
                # Suppress the false-positive "add secondary MX" advice
                recs.append(
                    Recommendation(
                        priority=5,
                        category="MX",
                        title=f"Single MX record — managed by {provider_name}",
                        description=(
                            f"{self.domain} has a single MX record pointing to {provider_name}. "
                            "This is the correct configuration — the provider operates a "
                            "geo-redundant infrastructure behind this single hostname. "
                            "Do not add a secondary MX, as this could bypass spam/malware "
                            "filtering or create routing conflicts."
                        ),
                        impact="No action needed. Redundancy is handled by the provider.",
                        fix="No change required. This is the vendor-recommended configuration.",
                        reference="https://datatracker.ietf.org/doc/html/rfc5321#section-5",
                    )
                )
            else:
                recs.append(
                    Recommendation(
                        priority=5,
                        category="MX",
                        title="Single MX record — no redundancy",
                        description=(
                            f"{self.domain} has only one MX record pointing to a self-hosted or "
                            "unrecognized mail server. If that server goes down, email delivery "
                            "will fail with no failover."
                        ),
                        impact="No failover for inbound email if the primary MX is unavailable.",
                        fix="Add a secondary MX record with a higher priority number.",
                        reference="https://datatracker.ietf.org/doc/html/rfc5321#section-5",
                    )
                )

        if all_starttls is False:
            no_tls = [mx.get("host", "?") for mx in mx_records if mx.get("starttls") in (False, None) and not mx.get("is_null_mx")]
            recs.append(
                Recommendation(
                    priority=2,
                    category="MX",
                    title="Not all MX hosts support STARTTLS",
                    description=(
                        f"The following MX hosts for {self.domain} do not support STARTTLS: "
                        f"{', '.join(no_tls)}. Email to/from these servers may be transmitted in plaintext."
                    ),
                    impact=(
                        "Email transmitted without TLS encryption is vulnerable to "
                        "eavesdropping and tampering."
                    ),
                    fix="Ensure STARTTLS is enabled on all mail servers.",
                    reference="https://datatracker.ietf.org/doc/html/rfc3207",
                )
            )

        if all_ptr is False:
            no_ptr = [mx.get("host", "?") for mx in mx_records if mx.get("ptr") is None and not mx.get("is_null_mx")]
            recs.append(
                Recommendation(
                    priority=4,
                    category="MX",
                    title="Not all MX hosts have valid PTR records",
                    description=(
                        f"The following MX hosts lack valid reverse DNS (PTR) records: "
                        f"{', '.join(no_ptr)}."
                    ),
                    impact=(
                        "Missing PTR records can cause some receiving mail servers to "
                        "reject or flag your emails as suspicious."
                    ),
                    fix="Configure PTR records for each MX host's IP address.",
                    reference="https://datatracker.ietf.org/doc/html/rfc5321#section-4.1.3",
                )
            )

        return recs

    # ---- DNSSEC ----

    def _check_dnssec(self):
        recs = []
        domain = self.result.get("DOMAIN", "this domain")
        dnskey_present = self.result.get("DNSSEC_DNSKEY_PRESENT", False)
        has_ds = self.result.get("DNSSEC_HAS_DS", False)
        enabled = self.result.get("DNSSEC_ENABLED", False)

        # State 1: Completely disabled — no DNSKEY, no DS
        if not dnskey_present and not has_ds:
            recs.append(Recommendation(
                priority=4,
                category="DNSSEC",
                title="DNSSEC is not enabled",
                description=(
                    f"The domain {domain} does not have DNSSEC enabled. "
                    "DNSSEC protects against DNS spoofing and cache poisoning by "
                    "cryptographically signing DNS records."
                ),
                impact=(
                    "Without DNSSEC, DNS responses can be forged by attackers "
                    "(man-in-the-middle), potentially redirecting email traffic "
                    "or undermining SPF/DKIM/DMARC validation."
                ),
                fix=(
                    "Enable DNSSEC signing at your DNS provider. Managed DNS services "
                    "that support one-click DNSSEC activation include:\n"
                    "  • Cloudflare (free tier)\n"
                    "  • Azure DNS\n"
                    "  • AWS Route 53\n"
                    "  • Google Cloud DNS\n"
                    "  • Simply.com / UnoEuro (DK)\n"
                    "  • DK Hostmaster (via registrar)\n\n"
                    "After enabling DNSSEC at the DNS host, add the DS record "
                    "to your domain registrar to complete the chain of trust."
                ),
                reference="https://www.icann.org/resources/pages/dnssec-what-is-it-why-is-it-important-2019-03-05-en",
            ))

        # State 2: Broken — DNSKEY present but no DS in parent zone
        elif dnskey_present and not has_ds:
            recs.append(Recommendation(
                priority=3,
                category="DNSSEC",
                title="DNSSEC chain of trust incomplete — no DS record in parent zone",
                description=(
                    f"The domain {domain} has DNSKEY records (DNSSEC signing is active) "
                    "but no DS record was found in the parent zone. This means the "
                    "chain of trust is not established."
                ),
                impact=(
                    "Without a DS record in the parent zone, resolvers cannot "
                    "validate the DNSSEC signatures. The signing is effectively "
                    "ignored by validating resolvers."
                ),
                fix=(
                    "Add the DS record to your domain registrar. The DS record is "
                    "generated from your DNSKEY and must be published in the parent "
                    "zone (e.g. .com). Your DNS provider should provide the DS record "
                    "values to submit to your registrar."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc4035#section-5.2",
            ))

        # State 3: Critical outage — DS exists but no DNSKEY (SERVFAIL)
        elif has_ds and not dnskey_present:
            recs.append(Recommendation(
                priority=1,
                category="DNSSEC",
                title="DNSSEC is BROKEN — DS record exists but no valid DNSKEY found",
                description=(
                    f"The parent zone requires DNSSEC for {domain} (DS record present), "
                    "but no valid DNSKEY records were found at the apex."
                ),
                impact=(
                    "CRITICAL OUTAGE: Validating resolvers (like 1.1.1.1 or 8.8.8.8) "
                    "will return SERVFAIL for all queries. Your domain is completely "
                    "unreachable for users on strict resolvers."
                ),
                fix=(
                    "Immediately publish the correct DNSKEY records matching your DS "
                    "record, or remove the DS record from your domain registrar to "
                    "disable DNSSEC."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc4035#section-5.2",
            ))

        # RFC 9904: Warn about deprecated cryptographic algorithms
        if enabled:
            has_weak_dnskey = self.result.get("DNSSEC_HAS_WEAK_DNSKEY", False)
            has_weak_ds = self.result.get("DNSSEC_HAS_WEAK_DS", False)
            if has_weak_dnskey or has_weak_ds:
                weak_parts = []
                if has_weak_dnskey:
                    weak_parts.append("DNSKEY algorithm")
                if has_weak_ds:
                    weak_parts.append("DS digest type (e.g. SHA-1)")
                recs.append(Recommendation(
                    priority=3,
                    category="DNSSEC",
                    title="DNSSEC uses deprecated cryptography (RFC 9904)",
                    description=(
                        f"The domain {domain} has DNSSEC enabled but uses deprecated "
                        f"cryptographic primitives: {', '.join(weak_parts)}. "
                        "RFC 9904 classifies these as MUST NOT or NOT RECOMMENDED."
                    ),
                    impact=(
                        "Deprecated algorithms like SHA-1 and RSAMD5 are vulnerable to "
                        "collision and pre-image attacks. An attacker could forge DS records "
                        "or DNSKEY signatures, undermining the entire DNSSEC chain of trust."
                    ),
                    fix=(
                        "Rotate to modern DNSSEC algorithms:\n"
                        "  • DNSKEY: Use Algorithm 13 (ECDSAP256SHA256) or 15 (Ed25519)\n"
                        "  • DS Digest: Use Digest Type 2 (SHA-256) or 4 (SHA-384)\n\n"
                        "Most DNS providers handle this automatically when you regenerate "
                        "DNSSEC keys. After rotation, update the DS record at your registrar."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc9904",
                ))

        return recs

    # ---- DANE ----

    def _check_dane(self):
        recs = []

        # Null MX (RFC 7505): domain intentionally receives no email.
        # DANE/TLSA is inapplicable — skip all recommendations.
        if self.result.get("MX_HAS_NULL_MX", False):
            return recs

        domain = self.result.get("DOMAIN", "this domain")
        dnssec_enabled = self.result.get("DNSSEC_ENABLED", False)
        has_tlsa = self.result.get("DANE_HAS_TLSA", False)
        dane_mx_count = self.result.get("DANE_MX_COUNT", 0)
        total_mx = self.result.get("DANE_TOTAL_MX", 0)
        has_bogus = self.result.get("DANE_HAS_BOGUS_RECORDS", False)
        has_unsupported = self.result.get("DANE_HAS_UNSUPPORTED_RECORDS", False)

        # RFC 7672 §3.1.3: Bogus DNSSEC = SERVFAIL = MTAs MUST abort connection.
        # This takes precedence regardless of whether TLSA records exist —
        # a broken NSEC/NSEC3 denial-of-existence proof triggers SERVFAIL too.
        if has_bogus:
            recs.append(Recommendation(
                priority=1,
                category="DANE",
                title="CRITICAL: DNSSEC validation for TLSA queries is BOGUS (SERVFAIL)",
                description=(
                    f"One or more MX hosts for {domain} returned a BOGUS (SERVFAIL) "
                    "response during DNSSEC validation of the TLSA query."
                ),
                impact=(
                    "Per RFC 7672 §3.1.3, DANE-aware MTAs (like Gmail and Outlook) "
                    "MUST abort the TLS connection when DNSSEC validation is bogus, "
                    "even if no TLSA records exist. Inbound email is being dropped "
                    "entirely by strict senders."
                ),
                fix=(
                    "Immediately fix the DNSSEC configuration for the affected MX "
                    "host. Check for expired RRSIG signatures or mismatched "
                    "DS/DNSKEY records."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc7672#section-3.1.3",
            ))

        # RFC 6698 §4.1: Unsupported parameters make records unusable
        if has_unsupported:
            recs.append(Recommendation(
                priority=2,
                category="DANE",
                title="DANE/TLSA records contain unsupported or malformed parameters",
                description=(
                    f"One or more TLSA records for MX hosts of {domain} contain "
                    "an unrecognized Usage, Selector, Matching Type, or an invalid "
                    "hash length."
                ),
                impact=(
                    "Per RFC 6698 §4.1, records with unrecognized parameters MUST "
                    "be considered 'unusable'. DANE-aware MTAs will ignore these records."
                ),
                fix=(
                    "Review your TLSA records and ensure: Usage is 0-3, Selector is "
                    "0-1, Matching Type is 0-2, and hash lengths match their algorithm "
                    "(32 bytes for SHA-256, 64 bytes for SHA-512)."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc6698#section-4.1",
            ))

        is_secure = self.result.get("DANE_IS_SECURE", False)

        # MX host's DNSSEC is missing (no AD flag) — TLSA records exist but unusable
        if has_tlsa and not is_secure and not has_bogus and not has_unsupported:
            recs.append(Recommendation(
                priority=3,
                category="DANE",
                title="DANE/TLSA records published but MX host zone lacks DNSSEC",
                description=(
                    f"TLSA records were found for the MX hosts of {domain}, but "
                    "the MX host's DNS zone is not secured with DNSSEC (AD flag "
                    "missing on the TLSA response)."
                ),
                impact=(
                    "Per RFC 6698 §4.1, TLSA records MUST be secured by DNSSEC. "
                    "Without it, receiving MTAs will consider your TLSA records "
                    "'unusable'."
                ),
                fix=(
                    "Enable DNSSEC on the DNS zone hosting your MX records, or "
                    "remove the ineffective TLSA records."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc6698#section-4.1",
            ))

        # RFC 7672 §3.1.3: Origin domain lacks DNSSEC → MX delegation insecure
        # Attackers can spoof MX records, routing mail to an unencrypted server
        # and completely bypassing DANE on the real MX host.
        if has_tlsa and is_secure and not dnssec_enabled:
            recs.append(Recommendation(
                priority=2,
                category="DANE",
                title="DANE is bypassable — your domain lacks DNSSEC",
                description=(
                    f"Secure TLSA records were found for the MX hosts of {domain}, "
                    f"but {domain} itself does not have DNSSEC enabled. The TLSA "
                    "records are likely published by your email provider (e.g. "
                    "Google, Microsoft), not by you."
                ),
                impact=(
                    "Per RFC 7672 §3.1.3, DANE requires your domain's MX records to "
                    "be authenticated by DNSSEC. Because your domain lacks DNSSEC, an "
                    "attacker can spoof your MX records and route mail to an unencrypted "
                    "server, completely bypassing the DANE protection on the real MX host."
                ),
                fix=(
                    "Enable DNSSEC for your domain at your DNS provider and publish "
                    "the DS record at your registrar."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc7672#section-3.1.3",
            ))

        # Partial TLSA coverage
        if has_tlsa and is_secure and dane_mx_count < total_mx:
            recs.append(Recommendation(
                priority=5,
                category="DANE",
                title="DANE/TLSA only covers some MX hosts",
                description=(
                    f"Only {dane_mx_count} of {total_mx} MX hosts for {domain} "
                    "have secure TLSA records."
                ),
                impact=(
                    "MX hosts without TLSA records can still be targeted by "
                    "man-in-the-middle attacks."
                ),
                fix=(
                    "Publish TLSA records for all MX hosts at _25._tcp.<mx-host>."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc7672",
            ))

        # No DANE at all — only suggest if DNSSEC is active
        elif not has_tlsa and dnssec_enabled:
            recs.append(Recommendation(
                priority=5,
                category="DANE",
                title="Consider adding DANE/TLSA for MX hosts",
                description=(
                    f"DNSSEC is enabled for {domain} but no DANE/TLSA records "
                    "were found. DANE uses TLSA records to cryptographically "
                    "bind TLS certificates to DNS."
                ),
                impact=(
                    "Without DANE, mail delivery relies solely on the CA system "
                    "for TLS certificate validation, which is susceptible to "
                    "compromise or misissuance."
                ),
                fix=(
                    "Publish TLSA records at _25._tcp.<mx-host> for each MX server. "
                    "Since DNSSEC is already active, DANE records will be automatically "
                    "validated by DANE-aware MTAs."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc7672",
            ))

        return recs

    # --- CAA Checks ---

    def _check_caa(self):
        recs = []
        caa_records = self.result.get("CAA_RECORDS", [])
        caa_error = self.result.get("CAA_ERROR")
        unknown_crit = self.result.get("CAA_HAS_UNKNOWN_CRITICAL", False)
        effective_domain = self.result.get("CAA_EFFECTIVE_DOMAIN", self.domain)
        error_domain = self.result.get("CAA_ERROR_DOMAIN") or self.domain
        deny_regular = self.result.get("CAA_DENY_ALL_REGULAR", False)
        deny_wildcard = self.result.get("CAA_DENY_ALL_WILDCARD", False)
        has_iodef = self.result.get("CAA_HAS_IODEF", False)
        has_contactemail = self.result.get("CAA_HAS_CONTACTEMAIL", False)
        has_contactphone = self.result.get("CAA_HAS_CONTACTPHONE", False)
        has_mx = self.result.get("MX_COUNT", 0) > 0

        if caa_error:
            recs.append(Recommendation(
                priority=1,
                category="CAA",
                title="CRITICAL OUTAGE: CAA DNS Lookup Failed (SERVFAIL)",
                description=f"While climbing the DNS tree to find CAA records for {self.domain}, the resolver encountered a SERVFAIL or timeout at {error_domain}.",
                impact="Per RFC 8659 §6, Certificate Authorities MUST 'fail closed' if they cannot definitively prove the absence of a CAA record. You will not be able to obtain or renew SSL/TLS certificates.",
                fix=f"Investigate your DNS hosting provider for outages or DNSSEC misconfigurations at {error_domain}.",
                reference="https://datatracker.ietf.org/doc/html/rfc8659#section-6",
            ))
            return recs

        if unknown_crit:
            recs.append(Recommendation(
                priority=1,
                category="CAA",
                title="CRITICAL: CAA Record contains an Unknown Critical Tag",
                description=f"A CAA record affecting {self.domain} contains a tag that is not standard, and its Critical flag (Bit 0) is set.",
                impact="Per RFC 8659 §4.5, if a CA encounters a critical flag on an unknown tag, it MUST NOT issue certificates. Issuance is currently blocked globally.",
                fix="Remove the Critical flag (set to 0 instead of 128) on the custom CAA tag, or remove the tag entirely if it is no longer needed.",
                reference="https://datatracker.ietf.org/doc/html/rfc8659#section-4.5",
            ))
            return recs

        if not caa_records:
            recs.append(Recommendation(
                priority=4,
                category="CAA",
                title="No CAA records found",
                description=(
                    f"The domain {self.domain} does not have any CAA (Certificate Authority "
                    "Authorization) records. CAA records specify which Certificate Authorities "
                    "(CAs) are allowed to issue SSL/TLS certificates for your domain."
                ),
                impact=(
                    "CAA reduces your exposure to CA mis-issuance and gives you a published, "
                    "auditable policy on which CAs may issue for your domain. Without it, "
                    "any CA worldwide is permitted to issue a certificate if domain validation "
                    "is passed — whether legitimately or fraudulently. While Certificate "
                    "Transparency (CT) logs catch most mis-issuance within minutes, CAA "
                    "provides defense-in-depth by preventing it at the source."
                ),
                fix=(
                    f'{self.domain}.  IN  CAA  0 issue "letsencrypt.org"\n\n'
                    "Replace 'letsencrypt.org' with the specific CA your organization uses.\n\n"
                    "To also block wildcard certificates (strict — use only if you don't issue wildcards):\n"
                    f'{self.domain}.  IN  CAA  0 issuewild ";"\n\n'
                    "To allow wildcards from a specific CA:\n"
                    f'{self.domain}.  IN  CAA  0 issuewild "letsencrypt.org"'
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc8659",
                eli5_explanation="CAA tells the internet exactly which companies are allowed to make 'ID cards' (certificates) for your website. Without it, a careless or compromised CA could issue a certificate for your domain.",
                business_risk="Without CAA, mis-issuance only becomes visible through CT log monitoring after the fact. CAA proactively blocks unauthorized CAs from issuing in the first place."
            ))
            return recs

        # --- Contextual warnings for domains that HAVE CAA records ---

        # Warn if deny-all is set on a domain with active MX/services
        if deny_regular and has_mx:
            recs.append(Recommendation(
                priority=2,
                category="CAA",
                title="CAA blocks all certificate issuance but domain has active MX records",
                description=(
                    f'The domain {self.domain} publishes issue ";" which explicitly blocks '
                    "ALL certificate issuance, yet it has active MX records indicating it "
                    "handles email. This will prevent TLS certificate renewal."
                ),
                impact="MTA-STS, DANE, and HTTPS for webmail/autodiscover will stop working when current certificates expire.",
                fix=(
                    f"If this is intentional (no-cert domain), remove the MX records. "
                    f"Otherwise, replace the deny-all with an explicit authorization:\n"
                    f'{self.domain}.  IN  CAA  0 issue "your-ca.example"'
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc8659#section-4.2",
            ))

        # Warn on inherited CAA
        if effective_domain and effective_domain != self.domain:
            recs.append(Recommendation(
                priority=5,
                category="CAA",
                title=f"CAA policy inherited from parent zone ({effective_domain})",
                description=(
                    f"No CAA records exist at {self.domain} itself. The effective policy is "
                    f"inherited from {effective_domain} via the RFC 8659 §3 tree walk."
                ),
                impact="If your CA usage at this subdomain differs from the parent zone's policy, certificate issuance may fail or be unexpectedly authorized.",
                fix=(
                    f"Consider publishing leaf-specific CAA records at {self.domain} "
                    f"to explicitly control issuance independently of {effective_domain}."
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc8659#section-3",
            ))

        # Recommend iodef if missing
        if not has_iodef:
            recs.append(Recommendation(
                priority=5,
                category="CAA",
                title="No CAA incident reporting endpoint (iodef) configured",
                description=(
                    "CAA supports an 'iodef' tag that instructs CAs to send you incident reports "
                    "when they receive certificate requests that violate your CAA policy."
                ),
                impact="Without iodef, unauthorized certificate requests against your domain will go undetected.",
                fix=(
                    f'{self.domain}.  IN  CAA  0 iodef "mailto:security@{self.domain}"'
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc8659#section-4.4",
            ))

        # Recommend contact records if missing
        if not has_contactemail:
            recs.append(Recommendation(
                priority=5,
                category="CAA",
                title="No CAA contact email published",
                description=(
                    "Publishing a 'contactemail' CAA record provides CAs with a direct "
                    "security contact for your domain, enabling faster incident response."
                ),
                impact="CAs may not be able to reach you quickly in case of a security incident.",
                fix=(
                    f'{self.domain}.  IN  CAA  0 contactemail "security@{self.domain}"'
                ),
                reference="https://datatracker.ietf.org/doc/html/rfc9495",
            ))

        return recs

    def to_list(self):
        """Return recommendations as a list of dicts."""
        return [r.to_dict() for r in self.recommendations]

    def __str__(self):
        if not self.recommendations:
            return "✅ No remediation items — email security posture looks good!"

        lines = [f"Remediation Recommendations ({len(self.recommendations)} items):", ""]
        for rec in self.recommendations:
            lines.append(f"  {rec.priority_label}  [{rec.category}] {rec.title}")
            lines.append(f"    Description: {rec.description}")
            lines.append(f"    Impact:      {rec.impact}")
            lines.append(f"    Fix:         {rec.fix}")
            lines.append(f"    Reference:   {rec.reference}")
            lines.append("")
        return "\n".join(lines)
