# -*- coding: utf-8 -*-
"""
modules/cve.py - Scanner "versions exposees & CVE".

Objectif (NON-INTRUSIF, 100% donnees publiques) :
  1. Recuperer les en-tetes HTTP + le HTML de la page d'accueil.
  2. Detecter des technologies/versions DIVULGUEES :
       - en-tete 'Server'        (ex: Apache/2.4.41, nginx/1.18.0)
       - en-tete 'X-Powered-By'  (ex: PHP/7.4.3)
       - generateur CMS dans le HTML (meta name="generator", ex: WordPress 5.8)
       - indices /wp-content/ (WordPress) sans forcement la version
  3. Pour chaque techno+version, interroger l'API GRATUITE NVD (sans cle)
     et remonter les CVE reelles (id + CVSS + resume court) -> gravite mappee.
  4. Si AUCUNE version n'est exposee -> finding 'ok' (c'est BON pour la securite).

Ce module NE PLANTE JAMAIS : chaque check est protege par try/except et
renvoie toujours au moins un finding, meme en cas d'erreur reseau/NVD.

Contrat : scan(domain: str, base_url: str) -> list[dict]
"""

import re
import time

import os as _os
import sys as _sys

# Permet aussi l'execution directe du module (python modules/xxx.py).
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import base
import utils

# ---------------------------------------------------------------------------
# Parametres NVD (API 2.0 gratuite, sans cle)
# ---------------------------------------------------------------------------
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Rate-limit gratuit NVD : ~5 requetes / 30s -> on reste tres prudent.
NVD_SLEEP_SECONDS = 6.5      # pause AVANT chaque appel NVD (sauf le 1er)
NVD_TIMEOUT = 20             # NVD est parfois lent
NVD_RESULTS_PER_PAGE = 5     # on ne veut que quelques CVE representatives
MAX_TECHS_TO_QUERY = 4       # borne le nombre d'appels NVD (evite les longues attentes)

# Correspondance PRECISE par version : on interroge NVD via CPE (virtualMatchString)
# au lieu de keywordSearch. keywordSearch remonte TOUTE CVE citant le mot -> faux
# positifs (ex: "php 8.3.33" matchait de vieilles CVE sans rapport). Le CPE ne
# remonte que les CVE dont la plage de versions affectees inclut la version detectee.
CPE_MAP = {
    "apache": "apache:http_server",
    "httpd": "apache:http_server",
    "nginx": "nginx:nginx",
    "php": "php:php",
    "wordpress": "wordpress:wordpress",
    "litespeed": "litespeedtech:litespeed_web_server",
    "openssl": "openssl:openssl",
    "lighttpd": "lighttpd:lighttpd",
    "iis": "microsoft:internet_information_services",
    "microsoft-iis": "microsoft:internet_information_services",
    "tomcat": "apache:tomcat",
    "nodejs": "nodejs:node.js",
    "node.js": "nodejs:node.js",
}


def _cpe_for(product):
    """Renvoie le 'vendor:product' CPE pour un produit detecte, ou None si inconnu."""
    return CPE_MAP.get((product or "").strip().lower())


# ---------------------------------------------------------------------------
# Detection des technologies/versions exposees
# ---------------------------------------------------------------------------
def _extract_server_version(server_header):
    """
    A partir de l'en-tete 'Server', renvoie une liste de tuples
    (produit_lisible, produit_nvd, version) pour les composants versionnes.

    Ex: "Apache/2.4.41 (Ubuntu)" -> [("Apache 2.4.41", "apache 2.4.41", "2.4.41")]
        "nginx/1.18.0"           -> [("nginx 1.18.0", "nginx 1.18.0", "1.18.0")]
        "LiteSpeed"              -> []  (pas de version)
    """
    techs = []
    if not server_header:
        return techs
    # Cherche tous les motifs produit/version type "Nom/1.2.3"
    for m in re.finditer(r'([A-Za-z][A-Za-z0-9_\-]*)\/([0-9]+(?:\.[0-9]+){1,3})', server_header):
        produit = m.group(1)
        version = m.group(2)
        lisible = "%s %s" % (produit, version)
        techs.append((lisible, "%s %s" % (produit.lower(), version), version))
    return techs


def _extract_powered_by(xpb_header):
    """
    A partir de 'X-Powered-By', renvoie une liste de tuples
    (produit_lisible, produit_nvd, version).

    Ex: "PHP/7.4.3"      -> [("PHP 7.4.3", "php 7.4.3", "7.4.3")]
        "PHP/7.4.3, ..." -> plusieurs
    """
    techs = []
    if not xpb_header:
        return techs
    for m in re.finditer(r'([A-Za-z][A-Za-z0-9_\-\.]*)\/([0-9]+(?:\.[0-9]+){1,3})', xpb_header):
        produit = m.group(1)
        version = m.group(2)
        lisible = "%s %s" % (produit, version)
        techs.append((lisible, "%s %s" % (produit.lower(), version), version))
    return techs


def _extract_generator(html):
    """
    Cherche la meta 'generator' dans le HTML et en extrait produit+version.

    Ex: <meta name="generator" content="WordPress 5.8" />
        -> [("WordPress 5.8", "wordpress 5.8", "5.8")]
    Renvoie aussi un signal WordPress sans version si /wp-content/ present.
    """
    techs = []
    if not html:
        return techs
    # meta name="generator" content="..."
    for m in re.finditer(
        r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        html, re.IGNORECASE
    ):
        content = m.group(1).strip()
        vm = re.search(r'([A-Za-z][A-Za-z0-9 _\-]*?)\s+v?([0-9]+(?:\.[0-9]+){0,3})', content)
        if vm:
            produit = vm.group(1).strip()
            version = vm.group(2).strip()
            lisible = "%s %s" % (produit, version)
            techs.append((lisible, "%s %s" % (produit.lower(), version), version))
        else:
            # Generateur present mais sans version numerique (ex "WordPress")
            techs.append((content, content.lower(), ""))
    return techs


def _detect_technologies(headers, html):
    """
    Agrege toutes les detections en une liste dedoublonnee de tuples
    (produit_lisible, produit_nvd, version, source).
    source = "Server" | "X-Powered-By" | "generator"
    """
    detected = []
    seen = set()

    def _add(items, source):
        for lisible, nvd_kw, version in items:
            key = nvd_kw
            if key in seen:
                continue
            seen.add(key)
            detected.append((lisible, nvd_kw, version, source))

    try:
        _add(_extract_server_version(headers.get("Server", "")), "Server")
    except Exception:
        pass
    try:
        _add(_extract_powered_by(headers.get("X-Powered-By", "")), "X-Powered-By")
    except Exception:
        pass
    try:
        _add(_extract_generator(html), "generator")
    except Exception:
        pass

    return detected


# ---------------------------------------------------------------------------
# Interrogation NVD
# ---------------------------------------------------------------------------
def _severity_from_cvss(score):
    """Mappe un score CVSS (0-10) vers la gravite du contrat."""
    try:
        s = float(score)
    except Exception:
        return "faible"
    if s >= 9.0:
        return "critique"
    if s >= 7.0:
        return "eleve"
    if s >= 4.0:
        return "moyen"
    return "faible"


def _extract_cvss(cve_obj):
    """
    Extrait (score, severite_texte) d'un objet CVE NVD 2.0.
    Cherche CVSS v3.1, puis v3.0, puis v2. Renvoie (None, "") si absent.
    """
    metrics = (cve_obj.get("metrics") or {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = (arr[0].get("cvssData") or {})
            return data.get("baseScore"), (data.get("baseSeverity") or "")
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        data = (arr[0].get("cvssData") or {})
        return data.get("baseScore"), (arr[0].get("baseSeverity") or "")
    return None, ""


def _english_summary(cve_obj):
    """Renvoie la description anglaise courte d'une CVE NVD."""
    for d in (cve_obj.get("descriptions") or []):
        if d.get("lang") == "en":
            txt = (d.get("value") or "").strip()
            return re.sub(r"\s+", " ", txt)
    descs = cve_obj.get("descriptions") or []
    if descs:
        return re.sub(r"\s+", " ", (descs[0].get("value") or "").strip())
    return ""


def _query_nvd(product, version, is_first_call):
    """
    Interroge NVD pour un produit + version.
    - Si le produit est connu (CPE_MAP) : correspondance PRECISE par version via
      virtualMatchString (cpe:2.3:a:vendor:product:version:*...). precise=True.
    - Sinon : repli sur keywordSearch (approximatif -> a verifier). precise=False.
    Respecte le rate-limit (time.sleep avant l'appel sauf le premier).
    Renvoie (liste_de_cve, erreur_str_ou_None, precise_bool).
    """
    if utils.requests is None:
        return [], "librairie requests indisponible", False

    if not is_first_call:
        time.sleep(NVD_SLEEP_SECONDS)

    cpe = _cpe_for(product)
    precise = bool(cpe and version)
    if precise:
        params = {
            "virtualMatchString": "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*" % (cpe, version),
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
        }
    else:
        params = {
            "keywordSearch": ("%s %s" % (product, version)).strip(),
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
        }
    headers = {"User-Agent": "RSSI-virtuel-PME/1.0 (audit externe non-intrusif)"}

    try:
        resp = utils.requests.get(
            NVD_ENDPOINT, params=params, headers=headers, timeout=NVD_TIMEOUT
        )
    except Exception as e:
        return [], "erreur reseau NVD: %s" % e, precise

    # Gestion explicite du rate-limit (429) : on attend et on retente 1 fois.
    if resp.status_code == 429:
        try:
            time.sleep(NVD_SLEEP_SECONDS * 2)
            resp = utils.requests.get(
                NVD_ENDPOINT, params=params, headers=headers, timeout=NVD_TIMEOUT
            )
        except Exception as e:
            return [], "rate-limit NVD (429), retry echoue: %s" % e, precise

    if resp.status_code != 200:
        return [], "NVD HTTP %s" % resp.status_code, precise

    try:
        data = resp.json()
    except Exception as e:
        return [], "reponse NVD illisible: %s" % e, precise

    cves = []
    for item in (data.get("vulnerabilities") or []):
        cve_obj = item.get("cve") or {}
        cve_id = cve_obj.get("id") or "CVE-?"
        score, sev_txt = _extract_cvss(cve_obj)
        summary = _english_summary(cve_obj)
        cves.append({
            "id": cve_id,
            "score": score,
            "severity_txt": sev_txt,
            "summary": summary,
        })
    return cves, None, precise


# ---------------------------------------------------------------------------
# Explication patron reutilisee
# ---------------------------------------------------------------------------
_PATRON_VERSION = (
    "Afficher la version exacte de votre logiciel, c'est comme afficher la marque "
    "et le modele de votre serrure : un cambrioleur sait exactement quelle faille "
    "utiliser."
)


# ---------------------------------------------------------------------------
# Point d'entree du scanner
# ---------------------------------------------------------------------------
def scan(domain: str, base_url: str) -> list:
    """
    Scanne les versions exposees et croise avec les CVE publiques (NVD).
    Retourne une liste de findings (jamais vide, ne plante jamais).
    """
    findings = []

    # --- 1) Recuperation en-tetes + HTML ------------------------------------
    resp = None
    try:
        resp = utils.fetch_url(base_url, timeout=10)
    except Exception:
        resp = None

    if resp is None:
        findings.append(base.make_finding(
            id="cve_fetch",
            category="CVE",
            title="Page d'accueil injoignable",
            severity="info",
            status="info",
            detail="Impossible de recuperer les en-tetes/HTML de %s (site injoignable "
                   "ou bloque). L'analyse des versions exposees n'a pas pu etre menee." % base_url,
            patron="Nous n'avons pas pu ouvrir votre site pour verifier les logiciels "
                   "qu'il annonce. Ce point sera a re-verifier quand le site repond.",
            reco="Verifiez que le site est bien accessible publiquement, puis relancez l'audit.",
            evidence="",
        ))
        return findings

    headers = {}
    try:
        headers = dict(resp.headers or {})
    except Exception:
        headers = {}
    html = ""
    try:
        html = resp.text or ""
    except Exception:
        html = ""

    # --- 2) Detection des technologies/versions -----------------------------
    detected = []
    try:
        detected = _detect_technologies(headers, html)
    except Exception as e:
        findings.append(base.make_finding(
            id="cve_detect_error",
            category="CVE",
            title="Erreur lors de la detection des versions",
            severity="info",
            status="info",
            detail="Exception pendant l'analyse des en-tetes/HTML : %s" % e,
            patron="Une anomalie technique a empeche l'analyse des logiciels exposes. "
                   "Le reste de l'audit reste valable.",
            reco="Relancer l'audit ; si le probleme persiste, verifier la reponse du site.",
            evidence="",
        ))
        detected = []

    # Signal WordPress via /wp-content/ meme sans version explicite
    wp_indice = bool(re.search(r'/wp-content/', html, re.IGNORECASE)) if html else False

    server_hdr = headers.get("Server", "")
    xpb_hdr = headers.get("X-Powered-By", "")

    # --- 3) Cas "rien d'expose" = BON ---------------------------------------
    versions_exposees = [t for t in detected if t[2]]  # celles qui ont une version
    if not versions_exposees:
        # Rien de versionne. On note tout de meme les indices non-versionnes.
        evidence_bits = []
        if server_hdr:
            evidence_bits.append("Server: %s" % server_hdr)
        if xpb_hdr:
            evidence_bits.append("X-Powered-By: %s" % xpb_hdr)
        if wp_indice:
            evidence_bits.append("indice /wp-content/ (WordPress) present, version non divulguee")

        findings.append(base.make_finding(
            id="cve_no_version",
            category="CVE",
            title="Aucune version logicielle divulguee",
            severity="ok",
            status="pass",
            detail="Aucun numero de version exploitable n'a ete trouve dans les en-tetes "
                   "HTTP (Server, X-Powered-By) ni dans la balise <meta generator>. "
                   + ("Un CMS WordPress est probable (/wp-content/) mais sa version n'est pas "
                      "affichee, ce qui est le bon comportement. " if wp_indice else "")
                   + "En-tetes observes -> Server=%r, X-Powered-By=%r." % (server_hdr, xpb_hdr),
            patron="Bonne nouvelle : votre site ne revele pas la version exacte de ses "
                   "logiciels. C'est exactement ce qu'on veut : un attaquant ne peut pas "
                   "deviner d'un coup d'oeil quelle faille tenter contre vous.",
            reco="Continuez a masquer les numeros de version (en-tetes ServerTokens/"
                 "expose_php off, suppression du meta generator). Rien a corriger ici.",
            evidence=" | ".join(evidence_bits),
        ))
        return findings

    # --- 4) Il y a des versions exposees : on les rapporte + on interroge NVD
    # 4a) Finding "exposition de versions" (le probleme de fond)
    liste_tech = ", ".join("%s (via %s)" % (t[0], t[3]) for t in versions_exposees)
    findings.append(base.make_finding(
        id="cve_versions_exposees",
        category="CVE",
        title="Versions logicielles exposees publiquement",
        severity="moyen",
        status="warn",
        detail="Le site divulgue les versions suivantes : %s. "
               "Ces informations facilitent le ciblage d'exploits connus." % liste_tech,
        patron=_PATRON_VERSION + " Votre site annonce publiquement : %s."
               % ", ".join(t[0] for t in versions_exposees),
        reco="Masquez les numeros de version : Apache 'ServerTokens Prod' + "
             "'ServerSignature Off', Nginx 'server_tokens off', PHP 'expose_php = Off', "
             "et retirez la balise <meta name=\"generator\">. Gardez surtout ces "
             "logiciels a jour.",
        evidence=("Server: %s | X-Powered-By: %s" % (server_hdr, xpb_hdr)).strip(" |"),
    ))

    # 4b) Interrogation NVD pour chaque techno versionnee (bornee)
    a_interroger = versions_exposees[:MAX_TECHS_TO_QUERY]
    premier_appel = True
    for lisible, nvd_kw, version, source in a_interroger:
        # produit = nvd_kw sans la version (ex "php 8.3.33" -> "php")
        produit = nvd_kw[:-len(version)].strip() if version and nvd_kw.endswith(version) else nvd_kw
        cves, err, precise = ([], None, False)
        try:
            cves, err, precise = _query_nvd(produit, version, premier_appel)
        except Exception as e:  # ceinture + bretelles
            cves, err, precise = [], "exception NVD: %s" % e, False
        premier_appel = False

        if err:
            findings.append(base.make_finding(
                id="cve_nvd_error_%s" % re.sub(r'[^a-z0-9]+', '_', nvd_kw.lower()),
                category="CVE",
                title="Consultation CVE indisponible pour %s" % lisible,
                severity="info",
                status="info",
                detail="La base publique NVD n'a pas pu etre interrogee pour '%s' "
                       "(%s). La version reste neanmoins exposee." % (nvd_kw, err),
                patron="Nous n'avons pas pu consulter la liste officielle des failles "
                       "connues pour %s (service momentanement indisponible). "
                       "L'important reste : cette version est visible et devrait etre "
                       "masquee et tenue a jour." % lisible,
                reco="Relancez l'audit plus tard pour obtenir la liste des failles, "
                     "et mettez ce composant a jour entre-temps.",
                evidence=nvd_kw,
            ))
            continue

        if not cves:
            findings.append(base.make_finding(
                id="cve_none_%s" % re.sub(r'[^a-z0-9]+', '_', nvd_kw.lower()),
                category="CVE",
                title="Aucune CVE listee pour %s" % lisible,
                severity="faible",
                status="warn",
                detail="La recherche NVD pour '%s' ne remonte aucune CVE directement "
                       "associee. La version reste toutefois exposee (voir finding "
                       "d'exposition)." % nvd_kw,
                patron="Aucune faille connue n'est ressortie pour %s, mais afficher sa "
                       "version reste une mauvaise habitude a corriger." % lisible,
                reco="Masquez la version et maintenez ce composant a jour.",
                evidence=nvd_kw,
            ))
            continue

        # Choisit la CVE la plus grave comme gravite du finding
        def _score_of(c):
            try:
                return float(c["score"]) if c["score"] is not None else -1.0
            except Exception:
                return -1.0

        cves_tries = sorted(cves, key=_score_of, reverse=True)
        pire = cves_tries[0]
        pire_score = _score_of(pire)
        severity = _severity_from_cvss(pire_score) if pire_score >= 0 else "faible"
        status = "warn"  # exposition d'une version vulnerable = avertissement
        # Correspondance approximative (mot-cle) -> on ne surclasse PAS en critique/eleve
        # pour eviter les faux positifs ; on marque clairement "a verifier".
        if not precise and severity in ("critique", "eleve"):
            severity = "moyen"
        note_fiab = "" if precise else " [correspondance approximative - A VERIFIER]"

        lignes = []
        for c in cves_tries:
            sc = c["score"] if c["score"] is not None else "N/A"
            resume = (c["summary"] or "")[:180]
            lignes.append("%s (CVSS %s) : %s" % (c["id"], sc, resume))
        methode = ("correspondance PRECISE par version (CPE)" if precise
                   else "recherche approximative par mot-cle (a confirmer)")
        detail_txt = ("NVD remonte %d CVE pour '%s' via %s. Les plus notables :\n- %s"
                      % (len(cves_tries), nvd_kw, methode, "\n- ".join(lignes)))

        pire_sc_txt = pire["score"] if pire["score"] is not None else "N/A"
        if precise:
            patron_txt = (
                "Votre site indique utiliser %s. Cette version precise est associee a des "
                "failles de securite deja publiees et connues des attaquants (la plus grave : "
                "%s, niveau %s/10). Concretement, un attaquant qui voit cette version sait "
                "immediatement quelles attaques tenter." % (lisible, pire["id"], pire_sc_txt)
            )
        else:
            patron_txt = (
                "Votre site indique utiliser %s. Des failles au nom proche existent (la plus "
                "notable : %s, niveau %s/10), mais la correspondance exacte avec VOTRE version "
                "doit etre verifiee par un technicien avant de conclure. Dans le doute, masquez "
                "la version et tenez le logiciel a jour." % (lisible, pire["id"], pire_sc_txt)
            )
        findings.append(base.make_finding(
            id="cve_%s" % re.sub(r'[^a-z0-9]+', '_', nvd_kw.lower()),
            category="CVE",
            title="Failles connues pour %s (%d CVE, pire CVSS %s)%s"
                  % (lisible, len(cves_tries), pire_sc_txt, note_fiab),
            severity=severity,
            status=status,
            detail=detail_txt,
            patron=patron_txt,
            reco="Mettez %s a jour vers une version recente et corrigee, PUIS masquez le "
                 "numero de version dans les en-tetes/HTML." % lisible,
            evidence="; ".join("%s CVSS=%s" % (c["id"], c["score"]) for c in cves_tries),
        ))

    return findings


# ---------------------------------------------------------------------------
# Execution directe : preuve que le module tourne sur la cible reelle
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    cible = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    clean, base_url = utils.normalize(cible)
    print("=== Scan CVE sur %s (%s) ===\n" % (clean, base_url))

    results = scan(clean, base_url)

    # Resume des technos detectees (re-fetch leger pour affichage console)
    r = utils.fetch_url(base_url, timeout=10)
    if r is not None:
        hdrs = dict(r.headers or {})
        print("En-tetes revelateurs :")
        print("  Server        = %r" % hdrs.get("Server", ""))
        print("  X-Powered-By  = %r" % hdrs.get("X-Powered-By", ""))
        wp = bool(re.search(r'/wp-content/', r.text or "", re.IGNORECASE))
        print("  Indice WP     = %s" % ("oui (/wp-content/)" if wp else "non"))
        gen = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
            r.text or "", re.IGNORECASE
        )
        print("  meta generator= %r" % (gen.group(1) if gen else ""))
    print()

    print("=== %d finding(s) ===" % len(results))
    for f in results:
        print("\n[%s/%s] %s" % (f["severity"].upper(), f["status"], f["title"]))
        print("  patron : %s" % f["patron"])
        print("  reco   : %s" % f["reco"])
        if f["evidence"]:
            print("  preuve : %s" % f["evidence"][:200])

    # Petit test de detection locale si un serveur tourne sur 127.0.0.1:8081
    try:
        local = utils.fetch_url("http://127.0.0.1:8081", timeout=3)
        if local is not None:
            print("\n=== Bonus: detection locale 127.0.0.1:8081 ===")
            lres = scan("127.0.0.1", "http://127.0.0.1:8081")
            for f in lres:
                print("  [%s] %s" % (f["severity"], f["title"]))
    except Exception:
        pass

    print("\ncve.py : execution terminee sans erreur.")
