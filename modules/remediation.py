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
        # Sort by priority (critical first)
        recs.sort(key=lambda r: r.priority)
        return recs

    # --- SPF Checks ---

    def _check_spf(self):
        recs = []
        spf = self.result.get("SPF")
        spf_all = self.result.get("SPF_MULTIPLE_ALLS")
        too_many = self.result.get("SPF_TOO_MANY_DNS_QUERIES", False)
        query_count = self.result.get("SPF_NUM_DNS_QUERIES", 0)

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
                        f'{self.domain}.  IN  TXT  "{spf.replace("+all", "-all")}"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
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
                        f'{self.domain}.  IN  TXT  "{spf.replace("?all", "-all")}"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7208#section-5.1",
                )
            )

        elif spf_all == "~all":
            recs.append(
                Recommendation(
                    priority=4,
                    category="SPF",
                    title='SPF uses "~all" — consider upgrading to "-all"',
                    description=(
                        f"The SPF record for {self.domain} uses softfail (~all). While this marks "
                        "unauthorized senders, it doesn't instruct receivers to reject them."
                    ),
                    impact=(
                        "Most modern mail providers treat ~all similarly to -all, but the strongest "
                        "protection comes from an explicit hard fail."
                    ),
                    fix=(
                        "When you're confident your SPF includes are complete, change '~all' to '-all':\n\n"
                        f'{self.domain}.  IN  TXT  "{spf.replace("~all", "-all")}"'
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
                )
            )

        return recs

    # --- DMARC Checks ---

    def _check_dmarc(self):
        recs = []
        dmarc = self.result.get("DMARC")
        policy = self.result.get("DMARC_POLICY")
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
                )
            )
            return recs

        if policy == "none":
            recs.append(
                Recommendation(
                    priority=2,
                    category="DMARC",
                    title='DMARC policy is "none" — no enforcement',
                    description=(
                        f"The DMARC policy for {self.domain} is set to 'none', which means "
                        "emails failing authentication are still delivered normally."
                    ),
                    impact=(
                        "The 'none' policy is useful for monitoring, but does not protect "
                        "against spoofing. Attackers can still send emails as your domain."
                    ),
                    fix=(
                        "Upgrade to 'quarantine' or 'reject' after reviewing DMARC reports:\n\n"
                        f'_dmarc.{self.domain}.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{self.domain}; pct=100"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                )
            )

        elif policy == "quarantine":
            recs.append(
                Recommendation(
                    priority=4,
                    category="DMARC",
                    title='DMARC policy is "quarantine" — consider upgrading to "reject"',
                    description=(
                        f"The DMARC policy for {self.domain} is set to 'quarantine'. "
                        "Failing emails are sent to spam/junk rather than rejected outright."
                    ),
                    impact=(
                        "Quarantine is good protection, but users may still see spoofed "
                        "emails in their spam folder. Reject is the strongest setting."
                    ),
                    fix=(
                        f'_dmarc.{self.domain}.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@{self.domain}; pct=100"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc7489#section-6.3",
                )
            )

        if pct and str(pct).strip() != "100":
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
                        "Increase pct to 100 when you're confident in your configuration:\n\n"
                        "Change 'pct={pct}' to 'pct=100' in your DMARC record."
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
                        "Attackers can spoof subdomains (e.g., mail.{self.domain}, support.{self.domain}) "
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
                        "  • Microsoft 365: Admin Center → Settings → Domains → Enable DKIM\n"
                        "  • Google Workspace: Admin Console → Apps → Gmail → Authenticate email\n"
                        "  • Custom: Generate a 2048-bit RSA key pair and publish the public key:\n"
                        f'    selector._domainkey.{self.domain}.  IN  TXT  "v=DKIM1; k=rsa; p=<public_key>"'
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc6376",
                )
            )

        # Check for weak keys
        if selectors:
            for sel in selectors:
                bits = sel.get("key_bits")
                selector_name = sel.get("selector", "unknown")
                if bits and bits < 2048:
                    recs.append(
                        Recommendation(
                            priority=2,
                            category="DKIM",
                            title=f"DKIM key '{selector_name}' is only {bits}-bit (weak)",
                            description=(
                                f"The DKIM selector '{selector_name}' for {self.domain} uses a "
                                f"{bits}-bit RSA key. Keys shorter than 2048 bits are considered weak "
                                "and may be factored by determined attackers."
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

        return recs

    # --- BIMI Checks ---

    def _check_bimi(self):
        recs = []
        bimi = self.result.get("BIMI_RECORD")
        dmarc_policy = self.result.get("DMARC_POLICY")

        if not bimi:
            # BIMI is optional, so this is low priority
            if dmarc_policy in ("quarantine", "reject"):
                recs.append(
                    Recommendation(
                        priority=5,
                        category="BIMI",
                        title="Consider adding a BIMI record for brand visibility",
                        description=(
                            f"The domain {self.domain} has strong DMARC enforcement but no BIMI record. "
                            "BIMI allows your brand logo to appear next to your emails in supporting clients."
                        ),
                        impact=(
                            "BIMI increases brand recognition and builds trust with recipients. "
                            "It's also a signal that your email authentication is mature."
                        ),
                        fix=(
                            f'default._bimi.{self.domain}.  IN  TXT  "v=BIMI1; l=https://{self.domain}/brand/logo.svg"\n\n'
                            "Requirements:\n"
                            "  • Logo must be in SVG Tiny Portable/Secure format\n"
                            "  • DMARC policy must be quarantine or reject\n"
                            "  • A Verified Mark Certificate (VMC) is recommended for Gmail"
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
        mta_sts_txt = self.result.get("MTA_STS_TXT")
        mta_sts_mode = self.result.get("MTA_STS_MODE")
        max_age = self.result.get("MTA_STS_MAX_AGE")
        tls_rpt = self.result.get("TLS_RPT_RECORD")

        if not mta_sts_txt:
            recs.append(
                Recommendation(
                    priority=4,
                    category="MTA-STS",
                    title="No MTA-STS policy configured",
                    description=(
                        f"The domain {self.domain} has no MTA-STS (Mail Transfer Agent Strict Transport Security) "
                        "policy. MTA-STS ensures inbound mail is delivered over TLS-encrypted connections."
                    ),
                    impact=(
                        "Without MTA-STS, SMTP connections to your mail servers can be downgraded "
                        "to unencrypted plaintext via man-in-the-middle attacks."
                    ),
                    fix=(
                        "1. Publish a TXT record:\n"
                        f'   _mta-sts.{self.domain}.  IN  TXT  "v=STSv1; id=20240101"\n\n'
                        "2. Host a policy file at https://mta-sts." + self.domain + "/.well-known/mta-sts.txt:\n"
                        "   version: STSv1\n"
                        "   mode: testing\n"
                        "   mx: *.your-mx-host.com\n"
                        "   max_age: 86400\n\n"
                        "3. After validation, change mode to 'enforce'."
                    ),
                    reference="https://datatracker.ietf.org/doc/html/rfc8461",
                )
            )
        else:
            if mta_sts_mode == "testing":
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

        if not tls_rpt:
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

        if mx_count == 1:
            recs.append(
                Recommendation(
                    priority=5,
                    category="MX",
                    title="Single MX record — no redundancy",
                    description=(
                        f"{self.domain} has only one MX record. If that server goes down, "
                        "email delivery will fail."
                    ),
                    impact="No failover for inbound email if the primary MX is unavailable.",
                    fix="Add a secondary MX record with a higher priority number.",
                    reference="https://datatracker.ietf.org/doc/html/rfc5321#section-5",
                )
            )

        if all_starttls is False:
            no_tls = [mx.get("host", "?") for mx in mx_records if mx.get("starttls") is False]
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
            no_ptr = [mx.get("host", "?") for mx in mx_records if mx.get("ptr") is None]
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
