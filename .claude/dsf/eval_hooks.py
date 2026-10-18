"""kauth-gos plassholdere i eval-scenarioene: {{ACCESS_TOKEN}} / {{ACCESS_TOKEN:<epost>}}
og {{REFRESH_TOKEN}} / {{REFRESH_TOKEN:<epost>}}.

Mange av kauths sikkerhetskrav handler om hva som skjer med et *ekte* token
(redirect etter innlogging, veksling til admin). Kjernens eval_runner kaller
`substitute(text, base_url)`; her logges det inn via magic-link mot
eval-serveren, og lenken leses fra mock-mailen i serverloggen. Scenariofilen ser
aldri hvordan tokenet ble skaffet, bare at det finnes.
"""
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(os.environ.get("CLAUDE_PLUGIN_ROOT", "")) / "bin"))
from eval_runner import http_request  # noqa: E402

EVAL_LOG = Path(os.environ.get("KAUTH_EVAL_LOG") or (Path(__file__).resolve().parents[2] / "data" / "eval" / "server.log"))
DEFAULT_TOKEN_USER = "eval-user@example.test"
_TOKEN_CACHE: dict[str, dict[str, str]] = {}
_PLACEHOLDER = re.compile(r"\{\{(ACCESS_TOKEN|REFRESH_TOKEN)(?::([^}\s]+))?\}\}")


class TokenError(Exception):
    """Kunne ikke skaffe token fra eval-serveren."""


def _acquire_tokens(email: str, base_url: str) -> dict[str, str]:
    if email in _TOKEN_CACHE:
        return _TOKEN_CACHE[email]
    start = EVAL_LOG.stat().st_size if EVAL_LOG.exists() else 0
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    http_request("POST", base_url + "/magic-login", form,
                 urllib.parse.urlencode({"email": email, "service": "eval"}).encode(), follow_redirects=False)
    link = None
    needle = re.compile(r"\[MAIL MOCK\] To: " + re.escape(email) + r" .*?Link: (\S+)")
    for _ in range(50):
        if EVAL_LOG.exists():
            with EVAL_LOG.open(encoding="utf-8", errors="replace") as f:
                f.seek(start)
                m = None
                for line in f:
                    m = needle.search(line) or m
            if m:
                link = m.group(1)
                break
        time.sleep(0.1)
    if not link:
        raise TokenError(
            f"fant ingen magic-lenke for {email} i {EVAL_LOG} — kjører eval-serveren via "
            "scripts/run-eval-server.sh, og er rate-limiten (3/15 min per e-post) brukt opp?")
    status, headers, _ = http_request("GET", link, follow_redirects=False)
    if status == 200:
        # 009: lenken er en bekreftelsesside (skannersikker). Innlogging skjer
        # først ved POST til samme URL, slik skjemaet på siden gjør i nettleseren.
        status, headers, _ = http_request("POST", link, {"Origin": base_url}, b"", follow_redirects=False)
    location = headers.get("location", "")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    frag = urllib.parse.parse_qs(urllib.parse.urlparse(location).fragment)
    access = (qs.get("token") or [""])[0]
    refresh = (qs.get("rt") or frag.get("rt") or [""])[0]
    if not access:
        raise TokenError(f"magic-lenken ga ikke token i Location ({status} {location[:80]!r})")
    _TOKEN_CACHE[email] = {"ACCESS_TOKEN": access, "REFRESH_TOKEN": refresh}
    return _TOKEN_CACHE[email]


def substitute(text: str, base_url: str) -> str:
    return _PLACEHOLDER.sub(
        lambda m: _acquire_tokens(m.group(2) or DEFAULT_TOKEN_USER, base_url)[m.group(1)], text)
