# -*- coding: utf-8 -*-
"""
modules/ssl_headers.py - Scanner SSL/TLS + En-tetes HTTP de securite.

Expose : scan(domain: str, base_url: str) -> list[dict]

Deux familles de checks NON-INTRUSIFS (aucune attaque, donnees publiques) :
  A) SSL/TLS via ssl + socket (stdlib, port 443) :
     - le site repond-il en HTTPS ?
     - date d'expiration du certificat (jours restants)
     - emetteur du certificat
     - concordance du nom (CN / SAN) avec le domaine
     - version du protocole TLS negociee (SSLv3/TLS1.0/1.1 = fail)
  B) En-tetes HTTP de securite via utils.fetch_url(base_url) :
     - Strict-Transport-Security (HSTS)
     - Content-Security-Policy (CSP)
     - X-Frame-Options
     - X-Content-Type-Options
     - Referrer-Policy
     - Permissions-Policy
     - En-tete Server qui divulgue une version
     - redirection HTTP -> HTTPS active

Chaque check est protege par try/except : le module ne plante JAMAIS et
renvoie toujours au moins un finding.
"""

import ssl
import socket
import datetime
import tempfile
import os

import os as _os
import sys as _sys

# Permet aussi l'execution directe du module (python modules/xxx.py).
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import base
from base import make_finding
import utils


# --------------------------------------------------------------------------
# Helpers internes
# --------------------------------------------------------------------------

def _verified_context():
    """
    Contexte TLS avec validation complete.

    On utilise en priorite le magasin de racines Mozilla fourni par ``certifi``
    (le meme que celui de requests) plutot que le magasin du systeme : sur
    certains postes Windows, le magasin local contient d'anciennes racines /
    intermediaires expires qui font echouer la validation d'une chaine
    pourtant correcte (faux positif "certificate has expired"). Le resultat
    devient ainsi reproductible d'une machine a l'autre.
    """
    try:
        import certifi  # dependance de requests
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _get_certificate(clean_domain, port=443, timeout=8):
    """
    Ouvre une connexion TLS et renvoie (cert_dict, tls_version, cipher, err).
    - cert_dict : le certificat parse (dict) ou None
    - tls_version : ex 'TLSv1.3' ou None
    - cipher : tuple info cipher ou None
    - err : message d'erreur si echec, sinon None
    """
    context = _verified_context()
    try:
        with socket.create_connection((clean_domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
                return cert, version, cipher, None
    except Exception as e:
        return None, None, None, str(e)


def _decode_der(der):
    """
    Decode un certificat DER en dict (comme getpeercert()) via la stdlib :
    DER -> PEM -> fichier temporaire -> ssl._ssl._test_decode_cert.
    Renvoie {} si echec.
    """
    if not der:
        return {}
    path = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        os.write(fd, pem.encode("ascii", "replace"))
        os.close(fd)
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.remove(path)
            except Exception:
                pass


def _get_certificate_novalidate(clean_domain, port=443, timeout=8):
    """
    Recupere le certificat SANS validation (utile si la chaine est cassee,
    le nom ne concorde pas ou le certificat feuille est expire) afin de
    pouvoir quand meme lire ses champs (expiration, emetteur, noms).

    Renvoie (cert_dict, tls_version, cipher, der).
    cert_dict est decode depuis le DER (via stdlib) et peut donc contenir
    notAfter / issuer / subject / subjectAltName meme en cas d'echec de
    validation de la chaine.
    """
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection((clean_domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                der = ssock.getpeercert(binary_form=True)
                cert = _decode_der(der)
                return cert, version, cipher, der
    except Exception:
        return None, None, None, None


def _utcnow():
    """Heure UTC courante (naive), comparable aux dates de certificat."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _parse_cert_datetime(value):
    """Parse une date de certificat ('Jun  1 12:00:00 2026 GMT') -> datetime UTC."""
    return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def _cert_names(cert):
    """Extrait la liste des noms (CN + SAN DNS) d'un certificat parse."""
    names = []
    try:
        for tup in cert.get("subject", ()):
            for k, v in tup:
                if k == "commonName":
                    names.append(v.lower())
    except Exception:
        pass
    try:
        for typ, val in cert.get("subjectAltName", ()):
            if typ.lower() == "dns":
                names.append(val.lower())
    except Exception:
        pass
    return names


def _name_matches(domain, names):
    """Verifie si domain concorde avec un des noms (gere wildcard *.exemple.com)."""
    domain = domain.lower()
    for n in names:
        if n == domain:
            return True
        if n.startswith("*."):
            base_n = n[2:]
            # *.exemple.com couvre www.exemple.com mais pas exemple.com
            if domain == base_n:
                continue
            if domain.endswith("." + base_n) and domain.count(".") == base_n.count(".") + 1:
                return True
    return False


def _issuer_org(cert):
    """Renvoie l'organisation emettrice du certificat."""
    try:
        for tup in cert.get("issuer", ()):
            for k, v in tup:
                if k in ("organizationName", "commonName"):
                    return v
    except Exception:
        pass
    return "inconnu"


# --------------------------------------------------------------------------
# FAMILLE A : SSL / TLS
# --------------------------------------------------------------------------

def _check_ssl(clean_domain, findings):
    cert, version, cipher, err = _get_certificate(clean_domain)

    # 1) Le site repond-il en HTTPS avec un certificat VALIDE ?
    if cert is None:
        # Tentative sans validation pour distinguer "pas de HTTPS du tout"
        # d'un "HTTPS present mais certificat invalide", et pour recuperer
        # les champs reels du certificat (expiration, emetteur, noms).
        cert2, version2, cipher2, der = _get_certificate_novalidate(clean_domain)
        if version2 is not None:
            err_low = (err or "").lower()
            leaf_expired = False
            try:
                if cert2 and cert2.get("notAfter"):
                    exp_tmp = _parse_cert_datetime(cert2["notAfter"])
                    leaf_expired = (exp_tmp - _utcnow()).days < 0
            except Exception:
                leaf_expired = False

            # Distinguer : chaine cassee (feuille encore valide) vs feuille expiree
            if "expired" in err_low and not leaf_expired and cert2.get("notAfter"):
                findings.append(make_finding(
                    id="ssl_cert_invalide",
                    category="SSL",
                    title="Chaine de certification incomplete / expiree",
                    severity="eleve",
                    status="fail",
                    detail=("Le port 443 repond en %s et le certificat du site est encore "
                            "valide (expire le %s), MAIS la validation de la chaine echoue : "
                            "%s. Un certificat intermediaire ou racine present dans la chaine "
                            "est expire ou manquant. Emetteur: %s."
                            % (version2, cert2.get("notAfter"), err, _issuer_org(cert2))),
                    patron=("Le cadenas de votre site est mal installe : le certificat "
                            "principal est bon mais la 'chaine de confiance' derriere est "
                            "cassee. Certains navigateurs et applications (surtout mobiles ou "
                            "anciens) afficheront 'Site non securise' et feront fuir une partie "
                            "de vos visiteurs. C'est un probleme d'installation, pas de "
                            "renouvellement."),
                    reco=("Reinstaller la chaine complete (fullchain) du certificat cote serveur "
                          "/ hebergeur pour inclure les intermediaires a jour. Verifier ensuite "
                          "avec un test SSL (ex: SSL Labs)."),
                    evidence=("erreur TLS: %s ; notAfter=%s" % (err, cert2.get("notAfter")))[:300],
                ))
            else:
                findings.append(make_finding(
                    id="ssl_cert_invalide",
                    category="SSL",
                    title="Certificat HTTPS present mais INVALIDE",
                    severity="critique",
                    status="fail",
                    detail=("Le port 443 repond en %s mais la validation du certificat "
                            "a echoue : %s. Cela signifie certificat expire, auto-signe, "
                            "chaine incomplete ou nom non concordant." % (version2, err)),
                    patron=("Le cadenas de securite de votre site est casse. Les navigateurs "
                            "affichent un gros avertissement rouge 'Site non securise' a vos "
                            "visiteurs, qui fuient immediatement. Vous perdez des clients et "
                            "de la credibilite."),
                    reco=("Renouveler / reparer le certificat SSL immediatement (Let's Encrypt "
                          "gratuit via votre hebergeur, ou certificat fourni par l'hebergeur). "
                          "Verifier que la chaine complete est installee."),
                    evidence=("erreur TLS : %s" % err)[:300],
                ))

            # On analyse quand meme expiration / emetteur / nom sur le cert de secours.
            if cert2:
                _analyze_cert_fields(clean_domain, cert2, findings)
            # On tente quand meme la version protocole ci-dessous.
            version = version2
        else:
            findings.append(make_finding(
                id="ssl_https_absent",
                category="SSL",
                title="Aucun HTTPS fonctionnel sur le port 443",
                severity="critique",
                status="fail",
                detail=("Impossible d'etablir une connexion TLS sur %s:443. Erreur : %s"
                        % (clean_domain, err)),
                patron=("Votre site n'a pas de connexion securisee (le petit cadenas). "
                        "Google penalise ces sites et les navigateurs affichent 'Non "
                        "securise'. Toute donnee saisie (formulaire, mot de passe) circule "
                        "en clair et peut etre volee."),
                reco=("Activer HTTPS via un certificat SSL (gratuit avec Let's Encrypt, "
                      "souvent en 1 clic chez l'hebergeur) et forcer la redirection HTTP->HTTPS."),
                evidence=("erreur : %s" % err)[:300],
            ))
            return  # rien d'autre a analyser sans TLS
    else:
        # Certificat valide -> on regarde son contenu.
        _analyze_cert_fields(clean_domain, cert, findings)

    # 5) Version du protocole TLS negociee (fail si obsolete)
    try:
        if version:
            weak = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
            if version in weak:
                findings.append(make_finding(
                    id="ssl_protocol",
                    category="SSL",
                    title="Protocole de chiffrement obsolete : %s" % version,
                    severity="eleve",
                    status="fail",
                    detail=("Le serveur negocie %s, un protocole considere comme non sur "
                            "et abandonne par les navigateurs modernes." % version),
                    patron=("La technologie de chiffrement de votre site est demodee et "
                            "vulnerable. Un pirate peut plus facilement intercepter les "
                            "echanges. Les navigateurs recents finiront par bloquer l'acces."),
                    reco="Configurer le serveur pour n'accepter que TLS 1.2 et TLS 1.3.",
                    evidence="version negociee=%s" % version,
                ))
            else:
                findings.append(make_finding(
                    id="ssl_protocol",
                    category="SSL",
                    title="Protocole de chiffrement moderne : %s" % version,
                    severity="ok",
                    status="pass",
                    detail="Le serveur negocie %s (moderne et sur)." % version,
                    patron=("La technologie de chiffrement de votre site est a jour et "
                            "sure. Rien a faire de ce cote."),
                    reco="Aucune action.",
                    evidence="version negociee=%s" % version,
                ))
    except Exception:
        pass


def _analyze_cert_fields(clean_domain, cert, findings):
    """Analyse expiration + emetteur + concordance du nom sur un cert parse."""
    # 2) Expiration
    try:
        not_after = cert.get("notAfter")
        exp = _parse_cert_datetime(not_after)
        now = _utcnow()
        days_left = (exp - now).days

        if days_left < 0:
            findings.append(make_finding(
                id="ssl_expiry",
                category="SSL",
                title="Certificat SSL EXPIRE",
                severity="critique",
                status="fail",
                detail="Le certificat a expire le %s (il y a %d jours)." % (not_after, -days_left),
                patron=("Votre certificat de securite est perime. Les visiteurs voient "
                        "un avertissement de securite effrayant et la plupart quittent "
                        "le site. C'est comme avoir la porte de la boutique bloquee."),
                reco="Renouveler le certificat SSL en urgence (automatiser le renouvellement).",
                evidence="notAfter=%s" % not_after,
            ))
        elif days_left < 15:
            findings.append(make_finding(
                id="ssl_expiry",
                category="SSL",
                title="Certificat SSL expire dans moins de 15 jours",
                severity="eleve",
                status="warn",
                detail="Le certificat expire le %s (dans %d jours)." % (not_after, days_left),
                patron=("Votre certificat de securite arrive tres bientot a expiration. "
                        "S'il expire, votre site affichera 'Non securise' et fera fuir "
                        "les clients. Il faut agir cette semaine."),
                reco="Renouveler le certificat maintenant et activer le renouvellement automatique.",
                evidence="notAfter=%s (J-%d)" % (not_after, days_left),
            ))
        elif days_left < 30:
            findings.append(make_finding(
                id="ssl_expiry",
                category="SSL",
                title="Certificat SSL expire dans moins de 30 jours",
                severity="moyen",
                status="warn",
                detail="Le certificat expire le %s (dans %d jours)." % (not_after, days_left),
                patron=("Votre certificat de securite expirera dans moins d'un mois. "
                        "Rien d'urgent aujourd'hui, mais il faut le renouveler avant "
                        "la date pour eviter toute coupure."),
                reco="Planifier le renouvellement et, idealement, l'automatiser.",
                evidence="notAfter=%s (J-%d)" % (not_after, days_left),
            ))
        else:
            findings.append(make_finding(
                id="ssl_expiry",
                category="SSL",
                title="Certificat SSL valide dans le temps",
                severity="ok",
                status="pass",
                detail="Le certificat est valide jusqu'au %s (%d jours restants)." % (not_after, days_left),
                patron=("Bonne nouvelle : le cadenas de securite de votre site est "
                        "valide et loin d'expirer. Rien a faire de ce cote."),
                reco="Verifier que le renouvellement automatique est bien actif.",
                evidence="notAfter=%s (J-%d)" % (not_after, days_left),
            ))
    except Exception as e:
        findings.append(make_finding(
            id="ssl_expiry",
            category="SSL",
            title="Date d'expiration du certificat illisible",
            severity="faible",
            status="warn",
            detail="Impossible d'analyser la date d'expiration : %s" % e,
            patron=("Nous n'avons pas pu lire la date de validite du cadenas de "
                    "securite. A verifier manuellement pour eviter une mauvaise surprise."),
            reco="Verifier manuellement la date d'expiration du certificat SSL.",
            evidence="",
        ))

    # 3) Emetteur
    try:
        issuer = _issuer_org(cert)
        findings.append(make_finding(
            id="ssl_issuer",
            category="SSL",
            title="Emetteur du certificat : %s" % issuer,
            severity="info",
            status="info",
            detail="Le certificat a ete emis par : %s." % issuer,
            patron=("Votre certificat de securite a ete delivre par %s, une autorite "
                    "reconnue. C'est une information, pas un probleme." % issuer),
            reco="Aucune action. Info fournie a titre de transparence.",
            evidence="issuer=%s" % issuer,
        ))
    except Exception:
        pass

    # 4) Concordance du nom
    try:
        names = _cert_names(cert)
        if _name_matches(clean_domain, names):
            findings.append(make_finding(
                id="ssl_name_match",
                category="SSL",
                title="Le certificat correspond bien au domaine",
                severity="ok",
                status="pass",
                detail="Le domaine %s figure dans le certificat (%s)." % (
                    clean_domain, ", ".join(names[:5]) or "n/a"),
                patron=("Le cadenas de securite est bien au nom de votre site. "
                        "Tout est coherent, aucun avertissement pour vos visiteurs."),
                reco="Aucune action.",
                evidence="noms=%s" % ", ".join(names[:8]),
            ))
        else:
            findings.append(make_finding(
                id="ssl_name_match",
                category="SSL",
                title="Le certificat ne correspond PAS au domaine",
                severity="eleve",
                status="fail",
                detail="Le domaine %s n'est pas dans les noms du certificat : %s" % (
                    clean_domain, ", ".join(names[:8]) or "aucun"),
                patron=("Le cadenas de securite est au nom d'un autre site que le votre. "
                        "Les navigateurs affichent une alerte de securite et vos "
                        "visiteurs pensent que le site est frauduleux."),
                reco="Emettre un certificat qui inclut exactement votre nom de domaine.",
                evidence="noms=%s" % ", ".join(names[:8]),
            ))
    except Exception:
        pass


# --------------------------------------------------------------------------
# FAMILLE B : EN-TETES HTTP DE SECURITE
# --------------------------------------------------------------------------

# (id, nom d'en-tete, titre absent, severity absent, explication patron, reco)
_SECURITY_HEADERS = [
    (
        "hdr_hsts", "Strict-Transport-Security",
        "En-tete HSTS absent",
        "moyen",
        ("Sans cette protection, un pirate present sur un wifi public (cafe, "
         "aeroport) peut intercepter ou detourner la connexion de vos visiteurs "
         "vers une fausse version de votre site."),
        "Ajouter l'en-tete Strict-Transport-Security (ex: max-age=31536000; includeSubDomains).",
    ),
    (
        "hdr_csp", "Content-Security-Policy",
        "En-tete Content-Security-Policy absent",
        "moyen",
        ("Cette protection empeche l'injection de scripts malveillants dans vos "
         "pages. Sans elle, un attaquant peut plus facilement afficher de faux "
         "formulaires ou voler des donnees de vos visiteurs."),
        "Definir une Content-Security-Policy adaptee (commencer en mode report-only).",
    ),
    (
        "hdr_xfo", "X-Frame-Options",
        "En-tete X-Frame-Options absent",
        "faible",
        ("Sans cette protection, votre site peut etre affiche dans un cadre cache "
         "sur un site pirate pour tromper vos visiteurs et leur faire cliquer sur "
         "des boutons a leur insu (clickjacking)."),
        "Ajouter X-Frame-Options: SAMEORIGIN (ou la directive frame-ancestors dans la CSP).",
    ),
    (
        "hdr_xcto", "X-Content-Type-Options",
        "En-tete X-Content-Type-Options absent",
        "faible",
        ("Sans cette protection, le navigateur peut mal interpreter certains "
         "fichiers et executer du code non prevu, ce qui ouvre la porte a des "
         "attaques."),
        "Ajouter X-Content-Type-Options: nosniff.",
    ),
    (
        "hdr_referrer", "Referrer-Policy",
        "En-tete Referrer-Policy absent",
        "faible",
        ("Sans cette protection, votre site peut divulguer aux autres sites les "
         "adresses exactes que visitent vos utilisateurs, ce qui pose un probleme "
         "de confidentialite."),
        "Ajouter Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    (
        "hdr_permissions", "Permissions-Policy",
        "En-tete Permissions-Policy absent",
        "faible",
        ("Sans cette protection, des scripts tiers pourraient acceder a des "
         "fonctions sensibles du navigateur (camera, micro, geolocalisation) de "
         "vos visiteurs."),
        "Ajouter Permissions-Policy pour restreindre camera, micro, geolocalisation, etc.",
    ),
]


def _check_headers(clean_domain, base_url, findings):
    resp = utils.fetch_url(base_url)

    if resp is None:
        findings.append(make_finding(
            id="hdr_unreachable",
            category="Headers",
            title="Site injoignable pour l'analyse des en-tetes",
            severity="moyen",
            status="warn",
            detail="utils.fetch_url a renvoye None pour %s." % base_url,
            patron=("Nous n'avons pas pu charger votre site pour verifier ses "
                    "protections. A verifier : le site est-il bien en ligne ?"),
            reco="Verifier que le site repond bien en HTTPS puis relancer l'analyse.",
            evidence="url=%s" % base_url,
        ))
        return

    try:
        headers = resp.headers
    except Exception:
        headers = {}

    # Presence / absence des en-tetes de securite
    for hid, hname, title_absent, sev_absent, patron_txt, reco_txt in _SECURITY_HEADERS:
        try:
            value = headers.get(hname)
            if value:
                findings.append(make_finding(
                    id=hid,
                    category="Headers",
                    title="%s present" % hname,
                    severity="ok",
                    status="pass",
                    detail="En-tete present : %s: %s" % (hname, value),
                    patron="Bonne pratique en place : la protection '%s' est activee." % hname,
                    reco="Aucune action.",
                    evidence="%s: %s" % (hname, str(value)[:200]),
                ))
            else:
                findings.append(make_finding(
                    id=hid,
                    category="Headers",
                    title=title_absent,
                    severity=sev_absent,
                    status="fail",
                    detail="L'en-tete de securite '%s' est absent de la reponse." % hname,
                    patron=patron_txt,
                    reco=reco_txt,
                    evidence="",
                ))
        except Exception as e:
            findings.append(make_finding(
                id=hid,
                category="Headers",
                title="Analyse de l'en-tete %s impossible" % hname,
                severity="info",
                status="info",
                detail="Erreur lors de l'analyse de %s : %s" % (hname, e),
                patron="Verification de la protection '%s' non aboutie." % hname,
                reco="A verifier manuellement.",
                evidence="",
            ))

    # En-tete Server qui divulgue une version
    try:
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")
        disclosed = "%s %s" % (server, x_powered)
        has_version = any(c.isdigit() for c in disclosed)
        if server or x_powered:
            if has_version:
                findings.append(make_finding(
                    id="hdr_server_version",
                    category="Headers",
                    title="Le serveur divulgue sa version logicielle",
                    severity="faible",
                    status="warn",
                    detail="En-tetes: Server=%r X-Powered-By=%r" % (server, x_powered),
                    patron=("Votre site annonce publiquement les versions exactes de ses "
                            "logiciels. Un pirate lit cette info pour cibler des failles "
                            "connues de ces versions precises. Autant ne pas lui faciliter "
                            "la tache."),
                    reco="Masquer/attenuer l'en-tete Server et supprimer X-Powered-By (config serveur).",
                    evidence=disclosed.strip()[:200],
                ))
            else:
                findings.append(make_finding(
                    id="hdr_server_version",
                    category="Headers",
                    title="En-tete Server sans version detaillee",
                    severity="ok",
                    status="pass",
                    detail="Server=%r X-Powered-By=%r (pas de numero de version expose)" % (server, x_powered),
                    patron=("Votre serveur ne divulgue pas sa version precise : bonne "
                            "pratique, cela complique la tache d'un attaquant."),
                    reco="Aucune action.",
                    evidence=disclosed.strip()[:200],
                ))
    except Exception:
        pass

    # Redirection HTTP -> HTTPS
    try:
        http_url = "http://" + clean_domain
        r = utils.fetch_url(http_url)
        if r is not None:
            final_url = str(getattr(r, "url", "") or "")
            if final_url.lower().startswith("https://"):
                findings.append(make_finding(
                    id="hdr_http_redirect",
                    category="Headers",
                    title="Redirection HTTP -> HTTPS active",
                    severity="ok",
                    status="pass",
                    detail="http://%s redirige vers %s." % (clean_domain, final_url),
                    patron=("Meme si un visiteur tape votre adresse sans 'https', il est "
                            "automatiquement bascule vers la version securisee. Parfait."),
                    reco="Aucune action.",
                    evidence="http -> %s" % final_url,
                ))
            else:
                findings.append(make_finding(
                    id="hdr_http_redirect",
                    category="Headers",
                    title="Pas de redirection automatique vers HTTPS",
                    severity="moyen",
                    status="fail",
                    detail="http://%s ne redirige pas vers HTTPS (url finale: %s)." % (
                        clean_domain, final_url or "inconnue"),
                    patron=("Un visiteur qui tape votre adresse sans 'https' reste sur une "
                            "connexion NON securisee. Ses donnees circulent en clair et "
                            "peuvent etre interceptees sur un reseau public."),
                    reco="Forcer la redirection permanente (301) de http:// vers https:// cote serveur.",
                    evidence="http -> %s" % (final_url or "n/a"),
                ))
        else:
            findings.append(make_finding(
                id="hdr_http_redirect",
                category="Headers",
                title="Test de redirection HTTP non concluant",
                severity="info",
                status="info",
                detail="Impossible de tester http://%s (pas de reponse)." % clean_domain,
                patron="Nous n'avons pas pu tester la bascule automatique vers la version securisee.",
                reco="Verifier manuellement que http:// redirige bien vers https://.",
                evidence="",
            ))
    except Exception:
        pass


# --------------------------------------------------------------------------
# ENTREE PUBLIQUE
# --------------------------------------------------------------------------

def scan(domain: str, base_url: str) -> list:
    """
    Lance les checks SSL/TLS + en-tetes HTTP de securite.
    Ne plante jamais : renvoie toujours au moins un finding.
    """
    findings = []

    # domaine propre (au cas ou l'appelant passe une valeur non normalisee)
    try:
        clean_domain, norm_base = utils.normalize(domain)
        if not base_url:
            base_url = norm_base
    except Exception:
        clean_domain = (domain or "").strip().lower()
        if not base_url:
            base_url = "https://" + clean_domain

    # Famille A : SSL / TLS
    try:
        _check_ssl(clean_domain, findings)
    except Exception as e:
        findings.append(make_finding(
            id="ssl_error",
            category="SSL",
            title="Erreur inattendue durant l'analyse SSL",
            severity="info",
            status="info",
            detail="Exception non prevue dans _check_ssl : %s" % e,
            patron="L'analyse du cadenas de securite n'a pas pu aboutir completement.",
            reco="Relancer l'analyse ; si le probleme persiste, verifier la connectivite.",
            evidence=str(e)[:200],
        ))

    # Famille B : En-tetes HTTP
    try:
        _check_headers(clean_domain, base_url, findings)
    except Exception as e:
        findings.append(make_finding(
            id="hdr_error",
            category="Headers",
            title="Erreur inattendue durant l'analyse des en-tetes",
            severity="info",
            status="info",
            detail="Exception non prevue dans _check_headers : %s" % e,
            patron="L'analyse des protections HTTP n'a pas pu aboutir completement.",
            reco="Relancer l'analyse ; verifier que le site est joignable.",
            evidence=str(e)[:200],
        ))

    # Garantie : au moins un finding
    if not findings:
        findings.append(make_finding(
            id="ssl_headers_empty",
            category="SSL",
            title="Aucun resultat SSL/en-tetes",
            severity="info",
            status="info",
            detail="Le scanner n'a produit aucun finding (cas inattendu).",
            patron="Aucune information de securite SSL/en-tetes n'a pu etre collectee.",
            reco="Verifier la connectivite et relancer.",
            evidence="",
        ))

    return findings


if __name__ == "__main__":
    import sys
    dom = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    cd, bu = utils.normalize(dom)
    for f in scan(cd, bu):
        print("%-9s %s" % (f["severity"], f["title"]))
