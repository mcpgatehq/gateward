"""Hard-coded attack pattern corpora for Gateward.

Rule 1 — ``INJECTION_PHRASES``: lowercase substrings, matched case-insensitively
against concatenated tool response text.

Rule 3 — ``DESTRUCTIVE_SHELL_PATTERNS``: compiled regexes (IGNORECASE) matched
against string values in ``params.arguments`` of client-to-server ``tools/call``.

Rule 4 — ``SECRETS_PATTERNS``: compiled regexes matched against tool response
text to catch credentials that a server might leak back to the agent.

Rule 5 — ``PATH_TRAVERSAL_PATTERNS``: compiled regexes matched against string
arguments in ``tools/call`` requests.

Rule 6 — ``SUSPICIOUS_DESCRIPTION_PATTERNS``: compiled regexes matched against
tool descriptions and parameter schemas from ``tools/list`` responses, to
catch poisoned tool definitions hiding instructions from humans but visible
to the LLM.

Rule 8 — ``decode_and_extract()``: decodes base64 / double-URL-encoded / hex
strings from text so the other pattern lists can be re-checked against
encoded payloads.

Rule 9 — ``SSRF_PATTERNS``: internal network, cloud metadata, and dangerous
protocol URL patterns.

Rule 10 — ``EXFIL_URL_PATTERNS``: URL shapes associated with data
exfiltration (webhooks, attacker infra, curl/wget with data parameters,
piping secrets to network tools).
"""
from __future__ import annotations

import base64
import re
import urllib.parse

INJECTION_PHRASES: list[str] = [
    "ignore previous instructions",
    "ignore the above",
    "disregard your instructions",
    "disregard all previous",
    "forget your instructions",
    "you are now",
    "you must now",
    "new instructions:",
    "system: override",
    "system override",
    "jailbreak",
    "do anything now",
    "print your system prompt",
    "reveal your instructions",
    "what are your instructions",
    "above instructions are",
    "actually, ignore",
    "stop. new task",
    "override: ",
    "admin mode enabled",
]

_DESTRUCTIVE_SHELL_SOURCES: list[str] = [
    r"\brm\s+-rf?\b",
    r"\brm\s+-fr?\b",
    r"\bDROP\s+TABLE\b",
    r"\bDROP\s+DATABASE\b",
    r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)",  # DELETE without WHERE
    r"\bTRUNCATE\s+TABLE\b",
    r"\bgit\s+push\s+.*--force\b",
    r"\bgit\s+push\s+.*-f\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bdd\s+if=.*of=/dev/",
    r"\bmkfs\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}",  # fork bomb
    r">\s*/dev/sda",
    r"\bchmod\s+-R\s+777\s+/",
]

DESTRUCTIVE_SHELL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(src, re.IGNORECASE) for src in _DESTRUCTIVE_SHELL_SOURCES
]

_SECRETS_SOURCES: list[str] = [
    r"sk-[a-zA-Z0-9]{20,}",
    r"sk-proj-[a-zA-Z0-9]{20,}",
    r"ghp_[a-zA-Z0-9]{36,}",
    r"gho_[a-zA-Z0-9]{36,}",
    r"github_pat_[a-zA-Z0-9_]{82,}",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN (RSA |OPENSSH |EC |PGP |DSA )?PRIVATE KEY",
    r"-----BEGIN CERTIFICATE-----",
    r"xox[bpas]-[a-zA-Z0-9\-]+",
    r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.",
    r"mongodb(\+srv)?://[^\s]+@",
    r"postgres(ql)?://[^\s]+@",
    r"mysql://[^\s]+@",
    r"redis://[^\s]*:[^\s]+@",
    r"Bearer\s+[a-zA-Z0-9_\-.]{20,}",
    r"(?i)api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}",
]

SECRETS_PATTERNS: list[re.Pattern[str]] = [re.compile(src) for src in _SECRETS_SOURCES]

_PATH_TRAVERSAL_SOURCES: list[str] = [
    r"\.\./\.\./",
    r"\.\.\%2[fF]\.\.\%2[fF]",
    r"\.\.\\\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/hosts",
    r"~/.ssh/",
    r"~/.aws/",
    r"~/.gnupg/",
    r"/proc/self/environ",
    r"\.env\b",
    r"id_rsa\b",
    r"id_ed25519\b",
    r"id_ecdsa\b",
    r"authorized_keys\b",
    r"\.pem\b",
]

PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [re.compile(src) for src in _PATH_TRAVERSAL_SOURCES]

_SUSPICIOUS_DESCRIPTION_SOURCES: list[str] = [
    r"<IMPORTANT>",
    r"<important>",
    r"<CRITICAL>",
    r"<SYSTEM>",
    r"(?i)ignore\s+(previous|all|prior|above)\s+(instructions|prompts|rules)",
    r"(?i)before\s+using\s+this\s+tool",
    r"(?i)side[\s_-]?effect",
    r"(?i)also\s+present\s+\w+\s+tool",
    r"(?i)must\s+(always\s+)?send\s+(all|every)",
    r"(?i)redirect.*to\s+\S+@",
    r"(?i)read\s+~/\.ssh",
    r"(?i)read\s+~/\.aws",
    r"(?i)read\s+~/\.gnupg",
    r"(?i)pass\s+(its|the)\s+contents?\s+(as|in)",
    r"(?i)include\s+(its|the)\s+contents?\s+(as|in)",
    r"(?i)without\s+(notifying|telling|informing|alerting)\s+(the\s+)?user",
    r"(?i)do\s+not\s+(tell|inform|notify|alert)",
    r"(?i)\bsecret(ly)?\b",
    r"(?i)\bcovert(ly)?\b",
    r"(?i)hidden\s+(instruction|command|task)",
    r"(?i)exfiltrat",
    r"(?i)steal\s+(the|all|any)",
    r"(?i)send\s+(to|all\s+data\s+to)\s+https?://",
]

SUSPICIOUS_DESCRIPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(src) for src in _SUSPICIOUS_DESCRIPTION_SOURCES
]

_SSRF_SOURCES: list[str] = [
    # Localhost variants
    r"https?://127\.",
    r"https?://localhost[:/]",
    r"https?://0\.0\.0\.0",
    r"https?://\[::1\]",
    # Cloud metadata endpoints
    r"https?://169\.254\.169\.254",
    r"https?://metadata\.google\.internal",
    r"https?://100\.100\.100\.200",
    # Internal networks (RFC 1918)
    r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"https?://172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}",
    r"https?://192\.168\.\d{1,3}\.\d{1,3}",
    # Dangerous protocols
    r"file://",
    r"gopher://",
    r"dict://",
    r"ftp://127\.",
    r"ftp://localhost",
    # DNS rebinding / tunnels
    r"https?://[0-9a-f]+\.nip\.io",
    r"https?://[0-9a-f]+\.sslip\.io",
    r"https?://[^\s]*\.burpcollaborator\.net",
    r"https?://[^\s]*\.ngrok\.",
]

SSRF_PATTERNS: list[re.Pattern[str]] = [re.compile(src, re.IGNORECASE) for src in _SSRF_SOURCES]

_EXFIL_URL_SOURCES: list[str] = [
    # curl/wget with sensitive param keys in URL
    r"(?i)curl\s+.*https?://.*[?&](data|key|token|secret|password|passwd|cred|exfil|leak|steal)=",
    r"(?i)wget\s+.*https?://.*[?&](data|key|token|secret|password|passwd)=",
    # curl with POST data
    r"(?i)curl\s+.*-d\s+.*https?://",
    r"(?i)curl\s+.*--data.*https?://",
    r"(?i)curl\s+.*-X\s+POST.*https?://",
    # fetch with suspicious params
    r"https?://[^\s]+[?&](exfil|steal|leak|dump|extract)=",
    # Piping sensitive files to network tools
    r"(?i)cat\s+[^|]*\|\s*(curl|wget|nc|netcat)",
    r"(?i)\$\(cat\s+[^)]*\.(pem|key|env|ssh|aws|gnupg)",
    # Long base64 blob in URL query param
    r"https?://[^\s]+[?&]\w+=[A-Za-z0-9+/]{100,}={0,2}",
    # Exfil-shaped hostnames
    r"https?://[^\s]*(webhook|hook|callback|exfil|collect|receive|steal)[^\s]*[?&]",
    # Known attacker/tunnel infrastructure
    r"https?://[^\s]*\.ngrok\.\w+",
    r"https?://[^\s]*\.burpcollaborator\.net",
    r"https?://[^\s]*requestbin\.",
    r"https?://[^\s]*hookbin\.",
    r"https?://[^\s]*pipedream\.",
]

EXFIL_URL_PATTERNS: list[re.Pattern[str]] = [re.compile(src) for src in _EXFIL_URL_SOURCES]

_ARGUMENT_INJECTION_SOURCES: list[str] = [
    # Subcommand execution via allowed interpreters
    r"(?i)\b(npx|node)\s+-(c|e)\s+",
    r"(?i)\b(python3?|ruby|perl|php)\s+-(c|e)\s+",
    r"(?i)--eval[\s=]",
    r"(?i)--exec[\s=]",
    r"(?i)npm\s+exec\s+",
    # Shell metacharacters — command substitution
    r"\$\([^)]+\)",
    r"`[^`]+`",
    # Pipe to dangerous commands
    r"\|\s*(bash|sh|zsh|dash|curl|wget|nc|netcat|ncat)\b",
    # Command chaining to dangerous commands
    r";\s*(curl|wget|bash|sh|rm|cat|nc|python|node|ruby)\b",
    r"&&\s*(curl|wget|bash|sh|rm|cat|nc|python|node)\b",
    # Git argument injection (CVE-2025-68144)
    r"(?i)--config\s*=?\s*core\.(sshCommand|hooksPath|gitProxy)",
    r"(?i)--upload-pack\s*=",
    r"(?i)--receive-pack\s*=",
    # Environment variable injection
    r"(?i)\bLD_PRELOAD\s*=",
    r"(?i)\bLD_LIBRARY_PATH\s*=",
    r"(?i)\bPYTHONPATH\s*=.*\bpython",
    r"(?i)\bNODE_OPTIONS\s*=",
    r"(?i)\benv\s+\w+=\S+\s+(bash|sh|python|node|ruby|perl)\b",
    # Process substitution
    r"<\([^)]+\)",
    r">\([^)]+\)",
]

ARGUMENT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(src) for src in _ARGUMENT_INJECTION_SOURCES
]


_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{40,})")


def decode_and_extract(text: str) -> list[str]:
    """Return plausibly-decoded plaintext fragments extracted from ``text``.

    Attempts base64, double-URL, and hex decoding. Each candidate is
    validated (non-empty, printable) before being returned. Failed decodes
    are silently skipped — this is a detection helper, not a parser, and an
    undecodable fragment is just noise we ignore.
    """
    decoded_parts: list[str] = []
    text = str(text)

    for match in _B64_RE.finditer(text):
        try:
            decoded = base64.b64decode(match.group(), validate=False).decode("utf-8", errors="ignore")
            if len(decoded) > 10 and any(c.isprintable() for c in decoded):
                decoded_parts.append(decoded)
        except Exception:
            pass

    if "%25" in text or "%2e%2e" in text.lower() or "%2f" in text.lower():
        try:
            decoded = urllib.parse.unquote(urllib.parse.unquote(text))
            if decoded != text:
                decoded_parts.append(decoded)
        except Exception:
            pass

    for match in _HEX_RE.finditer(text):
        try:
            decoded = bytes.fromhex(match.group(1)).decode("utf-8", errors="ignore")
            if len(decoded) > 10 and any(c.isprintable() for c in decoded):
                decoded_parts.append(decoded)
        except Exception:
            pass

    return decoded_parts
