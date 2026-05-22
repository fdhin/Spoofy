# tests/test_architecture.py

"""
Architecture Guard Tests

Enforces the invariants defined in ARCHITECTURE.md, SCHEMA.md, and UTILITIES.md
at the **source code level** using AST analysis. These tests catch violations
BEFORE they cause silent bugs:

  1. All DNS queries must use dns_utils (not inline resolver construction)
  2. All TXT parsing must use txt_utils (not str(rdata) or .split("p="))
  3. All DNS queries on internationalized domains must use IDNA encoding
  4. All result dict keys emitted by to_dict() must be registered in schema.py

These tests are intentionally strict. If a new module legitimately needs to
bypass a rule, add it to the appropriate allowlist with a comment explaining why.
"""

import ast
import os
import re
import unittest
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = PROJECT_ROOT / "modules"

# ── Allowlists ───────────────────────────────────────────────────────────────
# Files that are ALLOWED to construct resolvers directly.
# dns_utils.py: it IS the utility — it constructs resolvers by design.
# dns.py: SOA discovery bootstraps BEFORE a resolver utility exists for the domain.
# dnssec.py: uses CD flag + EDNS DO bit — needs custom resolver config not
#            supported by make_auth_resolver / make_recursive_resolver.
# dane.py: same as dnssec — CD-first discriminator pattern requires custom flags.
# dkim.py: DKIM brute-force uses a local resolver with no timeout overrides,
#          plus a hardcoded fallback resolver for cross-zone CNAME chasing.
# caa.py: tree-climbing crosses zone boundaries with a hybrid resolver config.
# m365.py: cross-zone tenant discovery with custom timeout.

RESOLVER_ALLOWLIST = {
    "dns_utils.py",
    "dns.py",
    "dnssec.py",
    "dane.py",
    "dkim.py",
    "caa.py",
    "m365.py",
}

# Files that are ALLOWED to skip IDNA encoding (they don't do DNS queries
# on user-supplied domains, or they delegate to another module that does).
IDNA_ALLOWLIST = {
    "dns_utils.py",    # IS the IDNA utility
    "txt_utils.py",    # no DNS queries
    "syntax.py",       # no DNS queries
    "scoring.py",      # no DNS queries
    "remediation.py",  # no DNS queries
    "report.py",       # no DNS queries
    "html_report.py",  # no DNS queries
    "pdf_report.py",   # no DNS queries
    "history.py",      # no DNS queries
    "schema.py",       # no DNS queries
    "subdomain.py",    # uses HTTP (crt.sh), not DNS
    "spoofing.py",     # pure logic, no DNS queries
    "__init__.py",     # package marker
}


class TestDnsUtilsCompliance(unittest.TestCase):
    """ARCHITECTURE.md §2: All DNS queries must use dns_utils resolvers."""

    def test_no_inline_resolver_construction(self):
        """Modules outside the allowlist must not construct dns.resolver.Resolver() directly.

        They should use dns_utils.make_auth_resolver() or make_recursive_resolver() instead.
        This catches the exact class of bug where a module constructs a resolver
        without fallback nameservers, timeouts, or consistent configuration.
        """
        violations = []

        for py_file in MODULES_DIR.glob("*.py"):
            if py_file.name in RESOLVER_ALLOWLIST:
                continue

            source = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                # Detect dns.resolver.Resolver() calls
                if isinstance(node, ast.Call):
                    call_str = _format_call(node)
                    if call_str and "resolver.Resolver" in call_str:
                        violations.append(
                            f"{py_file.name}:{node.lineno} — "
                            f"inline dns.resolver.Resolver() construction. "
                            f"Use dns_utils.make_auth_resolver() or "
                            f"make_recursive_resolver() instead."
                        )

        self.assertEqual(
            violations, [],
            "Modules must use dns_utils for resolver construction "
            "(ARCHITECTURE.md §2):\n" + "\n".join(violations)
        )


class TestTxtUtilsCompliance(unittest.TestCase):
    """ARCHITECTURE.md §3: All TXT parsing must use txt_utils."""

    def test_no_raw_rdata_string_replacement(self):
        """Modules must not use str(rdata).replace('"', '') to parse TXT records.

        This pattern injects spaces at the 255-byte boundary of multi-string
        TXT records. Use txt_utils.parse_txt_record(rdata) instead.
        """
        violations = []
        # Match: str(rdata).replace('"', '') or .replace('"', "")
        pattern = re.compile(
            r'str\s*\([^)]*rdata[^)]*\)\s*\.\s*replace\s*\(\s*[\'"]"[\'"]\s*,',
            re.IGNORECASE,
        )

        for py_file in MODULES_DIR.glob("*.py"):
            # Skip txt_utils.py itself — it IS the utility and its docstring
            # references the anti-pattern it replaces, causing a false positive.
            if py_file.name == "txt_utils.py":
                continue
            source = py_file.read_text(encoding="utf-8")
            for i, line in enumerate(source.splitlines(), 1):
                if pattern.search(line):
                    violations.append(
                        f"{py_file.name}:{i} — "
                        f"raw str(rdata).replace() detected. "
                        f"Use txt_utils.parse_txt_record(rdata) instead."
                    )

        self.assertEqual(
            violations, [],
            "Modules must use txt_utils.parse_txt_record() for TXT parsing "
            "(ARCHITECTURE.md §3):\n" + "\n".join(violations)
        )

    def test_no_tag_substring_splitting(self):
        """Modules must not use .split('p=') or .find('p=') to extract tag values.

        These patterns cause substring collisions (e.g. 'p=' matching inside 'sp=').
        Use txt_utils.parse_tag_value(record) instead.
        """
        violations = []
        # Match: .split("p=") or .find("p=") — but not .split("v=spf") which is ok
        # We specifically catch split/find on short DMARC/SPF tag names
        pattern = re.compile(
            r'\.\s*(?:split|find)\s*\(\s*[\'"](?:p|sp|rua|ruf|aspf|adkim|fo|pct)=[\'"]\s*\)',
        )

        for py_file in MODULES_DIR.glob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            for i, line in enumerate(source.splitlines(), 1):
                if pattern.search(line):
                    violations.append(
                        f"{py_file.name}:{i} — "
                        f"tag substring splitting detected. "
                        f"Use txt_utils.parse_tag_value(record) instead."
                    )

        self.assertEqual(
            violations, [],
            "Modules must use txt_utils.parse_tag_value() for tag extraction "
            "(ARCHITECTURE.md §3):\n" + "\n".join(violations)
        )


class TestIdnaCompliance(unittest.TestCase):
    """ARCHITECTURE.md §4: All DNS-querying modules must IDNA-encode domains."""

    def test_dns_modules_import_idna_encoder(self):
        """Every module that imports dns.resolver must also import encode_idna
        from dns_utils (unless it's in the allowlist).

        This catches the exact bug where bimi.py was querying DNS without
        encoding internationalized domains.
        """
        violations = []

        for py_file in MODULES_DIR.glob("*.py"):
            if py_file.name in IDNA_ALLOWLIST:
                continue

            source = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError:
                continue

            imports_dns_resolver = False
            imports_encode_idna = False

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if "dns.resolver" in alias.name:
                            imports_dns_resolver = True

                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    # Check for from .dns_utils import encode_idna
                    # or from modules.dns_utils import encode_idna
                    if "dns_utils" in module:
                        for alias in node.names:
                            if alias.name == "encode_idna":
                                imports_encode_idna = True
                    # Also catches: from .dns_utils import encode_idna as _encode_idna
                    if "dns_utils" in module:
                        for alias in node.names:
                            if "encode_idna" in alias.name:
                                imports_encode_idna = True
                    if "dns.resolver" in module or module == "dns":
                        imports_dns_resolver = True

            if imports_dns_resolver and not imports_encode_idna:
                violations.append(
                    f"{py_file.name} — imports dns.resolver but does not "
                    f"import encode_idna from dns_utils. "
                    f"Internationalized domains will silently fail."
                )

        self.assertEqual(
            violations, [],
            "DNS-querying modules must import encode_idna from dns_utils "
            "(ARCHITECTURE.md §4):\n" + "\n".join(violations)
        )


class TestSchemaCompliance(unittest.TestCase):
    """SCHEMA.md: All result dict keys must be registered in schema.py."""

    def _get_schema_keys(self):
        """Extract all string constants defined in schema.py."""
        schema_path = MODULES_DIR / "schema.py"
        source = schema_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        keys = set()
        for node in ast.walk(tree):
            # Module-level assignments: KEY_NAME = "KEY_NAME"
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, str) and target.id.isupper():
                            keys.add(node.value.value)

        # Also include keys from CATEGORY_DISPLAY_NAMES
        # and any dict values that are result keys
        return keys

    def _get_to_dict_keys(self, py_file):
        """Extract string keys returned from to_dict() methods in a module."""
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            return set()

        keys = set()
        for node in ast.walk(tree):
            # Find methods named to_dict
            if isinstance(node, ast.FunctionDef) and node.name == "to_dict":
                # Walk the method body for dict literals with string keys
                for child in ast.walk(node):
                    if isinstance(child, ast.Dict):
                        for key in child.keys:
                            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                # Only check UPPER_CASE keys (result dict convention)
                                if key.value == key.value.upper() and "_" in key.value:
                                    keys.add(key.value)
        return keys

    def test_all_to_dict_keys_registered_in_schema(self):
        """Every UPPER_CASE key returned by a to_dict() method must be
        defined as a constant in schema.py.

        This catches the scenario where a new module emits a result key
        that downstream consumers (scoring, remediation, reports) don't
        know about.
        """
        schema_keys = self._get_schema_keys()

        # Modules that don't emit result-level keys (internal or non-scan)
        skip_files = {"schema.py", "history.py", "__init__.py", "txt_utils.py", "dns_utils.py"}

        violations = []
        for py_file in MODULES_DIR.glob("*.py"):
            if py_file.name in skip_files:
                continue

            to_dict_keys = self._get_to_dict_keys(py_file)
            for key in sorted(to_dict_keys):
                if key not in schema_keys:
                    violations.append(
                        f"{py_file.name} — to_dict() emits '{key}' "
                        f"which is not registered in schema.py"
                    )

        self.assertEqual(
            violations, [],
            "All result dict keys must be registered in modules/schema.py "
            "(SCHEMA.md):\n" + "\n".join(violations)
        )

    def test_orchestrator_keys_registered(self):
        """String keys used in spoofy.py result dicts must be registered in schema.py.

        Catches phantom keys in error stubs and the main result dict — e.g.
        SECURITY_GRADE (which doesn't exist) instead of SECURITY_POSTURE.
        """
        schema_keys = self._get_schema_keys()
        spoofy_path = PROJECT_ROOT / "spoofy.py"
        source = spoofy_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(spoofy_path))

        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key in node.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        kv = key.value
                        # Only check UPPER_CASE keys (result dict convention)
                        if kv == kv.upper() and "_" in kv and kv not in schema_keys:
                            violations.append(
                                f"spoofy.py:{key.lineno} — result dict key "
                                f"'{kv}' is not registered in schema.py"
                            )

        self.assertEqual(
            violations, [],
            "All result dict keys in spoofy.py must be registered in "
            "modules/schema.py (SCHEMA.md):\n" + "\n".join(violations)
        )

class TestImportConventions(unittest.TestCase):
    """ARCHITECTURE.md §9: modules/ must use relative imports."""

    def test_modules_use_relative_imports_for_utilities(self):
        """Modules within the modules/ package should use relative imports
        for txt_utils and dns_utils, not absolute imports.
        """
        violations = []
        for py_file in MODULES_DIR.glob("*.py"):
            if py_file.name in ("__init__.py", "dns_utils.py", "txt_utils.py", "schema.py"):
                continue

            source = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    # Catch: from modules.txt_utils import ... (should be from .txt_utils)
                    # Catch: from modules.dns_utils import ... (should be from .dns_utils)
                    if module.startswith("modules.") and any(
                        util in module for util in ("txt_utils", "dns_utils", "schema")
                    ):
                        violations.append(
                            f"{py_file.name}:{node.lineno} — "
                            f"absolute import '{module}' detected. "
                            f"Use relative import (e.g. from .{module.split('.')[-1]} import ...) "
                            f"inside modules/ package."
                        )

        self.assertEqual(
            violations, [],
            "Modules within modules/ must use relative imports "
            "(ARCHITECTURE.md §9):\n" + "\n".join(violations)
        )


# ── AST Helpers ──────────────────────────────────────────────────────────────

def _format_call(node):
    """Try to reconstruct a call expression as a string for matching.

    Returns a best-effort string like 'dns.resolver.Resolver' or None
    if the call structure is too complex.
    """
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    elif isinstance(func, ast.Attribute):
        parts.append(func.attr)

    if parts:
        return ".".join(reversed(parts))
    return None


if __name__ == "__main__":
    unittest.main()
