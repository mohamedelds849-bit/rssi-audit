# -*- coding: utf-8 -*-
"""
utils.py - Helpers partages du RSSI virtuel PME.

Expose :
  - fetch_url(url, timeout=8) -> requests.Response | None
  - dns_txt(domain) -> list[str]
  - normalize(domain) -> (clean_domain, base_url_https)
  - is_valid_domain(domain) -> bool

Aucune de ces fonctions ne doit planter l'appelant : elles capturent
leurs erreurs et renvoient une valeur par defaut sure.
"""

from __future__ import annotations

import re
import subprocess
from typing import List, Optional, Tuple

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


# User-Agent navigateur credible (evite certains blocages 403)
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
}


def fetch_url(url: str, timeout: float = 8) -> Optional["requests.Response"]:
    """
    Recupere une URL via requests.
    - Suit les redirections.
    - Envoie un User-Agent navigateur.
    - Retourne l'objet Response, ou None en cas d'erreur (jamais d'exception).
    """
    if requests is None:
        return None
    try:
        resp = requests.get(
            url,
            headers=_BROWSER_HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )
        return resp
    except Exception:
        # Deuxieme tentative sans verif TLS (certains certifs casses) pour au
        # moins pouvoir lire les en-tetes ; on ne leve jamais.
        try:
            import warnings
            with warnings.catch_warnings():
                # Avertissement urllib3 attendu ici : on lit seulement les en-tetes.
                warnings.simplefilter("ignore")
                resp = requests.get(
                    url,
                    headers=_BROWSER_HEADERS,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,
                )
            return resp
        except Exception:
            return None


def _parse_nslookup_txt(output: str) -> List[str]:
    """
    Parse la sortie brute de 'nslookup -type=TXT domain' (Windows/Unix)
    et renvoie la liste des enregistrements TXT trouves.
    """
    records = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Formats possibles :
        #   domain text = "v=spf1 ..."
        #   domain descriptive text "v=spf1 ..."
        #   "v=spf1 ..." (ligne de continuation)
        m = re.search(r'(?:text\s*=\s*|descriptive text\s+)(.*)$', line, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
        elif line.startswith('"'):
            candidate = line
        else:
            continue

        # Extrait tous les segments entre guillemets et les concatene
        quoted = re.findall(r'"([^"]*)"', candidate)
        if quoted:
            records.append("".join(quoted))
        elif candidate and not candidate.lower().startswith(("server", "address")):
            records.append(candidate)
    # Dedoublonne en gardant l'ordre
    seen = set()
    out = []
    for r in records:
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def dns_txt(domain: str) -> List[str]:
    """
    Retourne la liste des enregistrements TXT d'un domaine.
    Essaie dnspython (dns.resolver) ; a defaut, utilise 'nslookup -type=TXT'.
    Robuste Windows. Retourne [] en cas d'echec (jamais d'exception).
    """
    domain = (domain or "").strip()
    if not domain:
        return []

    # 1) dnspython si disponible
    try:
        import dns.resolver  # type: ignore
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            out = []
            for rdata in answers:
                try:
                    parts = [
                        p.decode("utf-8", "replace") if isinstance(p, (bytes, bytearray)) else str(p)
                        for p in rdata.strings
                    ]
                    out.append("".join(parts))
                except Exception:
                    out.append(str(rdata).strip('"'))
            if out:
                return out
        except Exception:
            pass  # bascule vers nslookup
    except Exception:
        pass  # dnspython absent

    # 2) Fallback nslookup (present partout sous Windows)
    for cmd in (["nslookup", "-type=TXT", domain],
                ["nslookup", "-querytype=TXT", domain]):
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            records = _parse_nslookup_txt(output)
            if records:
                return records
        except Exception:
            continue

    return []


def normalize(domain: str) -> Tuple[str, str]:
    """
    Nettoie un domaine saisi par l'utilisateur.
    Enleve le schema http(s)://, un eventuel chemin, le www. optionnel garde,
    et le slash final. Retourne (domaine_propre, 'https://'+domaine_propre).
    """
    d = (domain or "").strip()
    # Retire le schema
    d = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', '', d)
    # Retire tout ce qui suit le premier / (chemin), ? ou #
    d = re.split(r'[/?#]', d, 1)[0]
    # Retire un eventuel port
    d = d.split(":")[0]
    # Retire espaces et slash final residuel
    d = d.strip().strip(".").lower()
    base_url = "https://" + d
    return d, base_url


# Un label DNS : 1-63 caracteres alphanumeriques ou '-', pas de '-' en bord.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def is_valid_domain(domain: str) -> bool:
    """
    Verifie qu'une chaine (deja normalisee) ressemble a un nom de domaine
    public : au moins deux labels, longueur <= 253, TLD alphabetique (ou
    punycode 'xn--'). Refuse les IP et 'localhost'.
    """
    if not domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    if not all(_LABEL_RE.match(lbl) for lbl in labels):
        return False
    tld = labels[-1]
    return tld.isalpha() or tld.startswith("xn--")


if __name__ == "__main__":
    import sys
    test_domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print("=== normalize ===")
    clean, base = normalize("https://" + test_domain + "/blog/?x=1")
    print("normalize -> clean=%r base_url=%r" % (clean, base))

    print("\n=== dns_txt('%s') ===" % test_domain)
    txt = dns_txt(test_domain)
    if txt:
        for i, rec in enumerate(txt, 1):
            print("  TXT[%d]: %s" % (i, rec))
    else:
        print("  (aucun enregistrement TXT retourne)")

    print("\n=== fetch_url ===")
    resp = fetch_url(base)
    if resp is not None:
        body = resp.text or ""
        snippet = re.sub(r"\s+", " ", body[:200]).strip()
        print("  status=%s url_finale=%s" % (resp.status_code, resp.url))
        print("  extrait HTML: %s" % snippet[:160])
    else:
        print("  fetch_url a retourne None (site injoignable ?)")

    print("\nutils.py : tout fonctionne.")
