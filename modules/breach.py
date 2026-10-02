# -*- coding: utf-8 -*-
"""
modules/breach.py - Scanner "Fuites de donnees connues" du RSSI virtuel PME.

Objectif : verifier, SANS aucune API PAYANTE et de facon NON-INTRUSIVE, si le
domaine de l'entreprise apparait dans la liste PUBLIQUE et GRATUITE des fuites
de donnees recensees par Have I Been Pwned (HIBP).

Sources utilisees (100% gratuites, sans cle) :
  - https://haveibeenpwned.com/api/v3/breaches
    Endpoint PUBLIC listant toutes les fuites connues dans le monde. Chaque
    entree contient notamment un champ "Domain" (le site pirate/concerne),
    "Name", "Title", "BreachDate", "PwnCount" (nb de comptes), etc.

Ce qu'on NE fait PAS :
  - On n'interroge JAMAIS l'endpoint compte-par-compte
    (https://haveibeenpwned.com/api/v3/breachedaccount/<email>) car il exige
    une cle PAYANTE. On se contente de le signaler en option (finding info).

Contrat : def scan(domain, base_url) -> list[dict]
  - Ne plante jamais (try/except par check).
  - Renvoie au moins un finding, meme en cas d'erreur reseau.
"""

import json

# Import du socle et des helpers (compatible import direct ou via package)
try:
    from base import make_finding
    import utils
except Exception:  # pragma: no cover
    import os
    import sys
    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    from base import make_finding
    import utils


HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"


def _fetch_breaches():
    """
    Recupere la liste JSON des fuites connues via l'endpoint public HIBP.
    Retourne (liste_de_dicts | None, message_erreur | None).
    N'utilise JAMAIS de cle : cet endpoint est public.
    """
    try:
        resp = utils.fetch_url(HIBP_BREACHES_URL, timeout=12)
        if resp is None:
            return None, "Aucune reponse (site injoignable ou reseau bloque)."
        if resp.status_code != 200:
            return None, "Reponse HTTP %s inattendue." % resp.status_code
        try:
            data = resp.json()
        except Exception:
            try:
                data = json.loads(resp.text)
            except Exception as e:
                return None, "Reponse non-JSON (%s)." % e
        if not isinstance(data, list):
            return None, "Format de reponse inattendu (liste attendue)."
        return data, None
    except Exception as e:
        return None, "Exception reseau : %s" % e


def _root_label(clean_domain):
    """
    Retourne le 'nom' de l'entreprise (etiquette avant le TLD).
    ex: 'example.com' -> 'example'
    """
    d = (clean_domain or "").strip().lower()
    if not d:
        return ""
    parts = d.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def scan(domain: str, base_url: str) -> list:
    """
    Scanner de fuites de donnees connues.

    Args:
        domain   : domaine propre (ex 'example.com')
        base_url : URL https de base (non utilisee ici, gardee pour l'uniformite)

    Returns:
        list[dict] : findings conformes au contrat make_finding.
    """
    findings = []
    clean = (domain or "").strip().lower()
    name = _root_label(clean)

    breaches, err = _fetch_breaches()

    # --- Cas d'erreur : API indisponible -> on ne plante pas ------------------
    if breaches is None:
        try:
            findings.append(make_finding(
                id="breach_api_unavailable",
                category="Breach",
                title="Verification des fuites connues indisponible pour le moment",
                severity="info",
                status="info",
                detail=(
                    "Impossible de recuperer la liste publique des fuites HIBP "
                    "(%s). L'endpoint utilise est gratuit et sans cle : "
                    "%s" % (err, HIBP_BREACHES_URL)
                ),
                patron=(
                    "Nous n'avons pas pu consulter la base mondiale des piratages "
                    "connus au moment de l'audit (probleme de reseau temporaire). "
                    "Ce n'est pas un signe de danger : il suffit de relancer "
                    "l'analyse plus tard pour obtenir ce point."
                ),
                reco="Relancer l'audit plus tard (probleme reseau/temporaire).",
                evidence=str(err or ""),
            ))
        except Exception:
            pass
        return findings

    total = len(breaches)

    # --- 1) Recherche du domaine de l'entreprise dans les fuites --------------
    matches = []
    try:
        for b in breaches:
            if not isinstance(b, dict):
                continue
            bdomain = str(b.get("Domain", "") or "").strip().lower()
            btitle = str(b.get("Title", "") or "")
            bname = str(b.get("Name", "") or "")
            if not bdomain:
                continue
            # Correspondance exacte du domaine, OU le domaine de l'entreprise
            # est un sous/super-domaine de l'entree (ex apex vs www).
            hit = False
            if bdomain == clean:
                hit = True
            elif clean and (bdomain.endswith("." + clean) or clean.endswith("." + bdomain)):
                hit = True
            if hit:
                matches.append({
                    "Domain": bdomain,
                    "Title": btitle or bname,
                    "Name": bname,
                    "BreachDate": str(b.get("BreachDate", "") or ""),
                    "PwnCount": b.get("PwnCount", 0),
                    "DataClasses": b.get("DataClasses", []),
                })
    except Exception as e:
        try:
            findings.append(make_finding(
                id="breach_parse_error",
                category="Breach",
                title="Analyse partielle de la base de fuites",
                severity="info",
                status="info",
                detail="Erreur pendant l'analyse des fuites : %s" % e,
                patron=(
                    "L'analyse des piratages connus a rencontre un souci technique "
                    "mineur. Le reste du rapport reste fiable."
                ),
                reco="Relancer l'audit pour une verification complete.",
                evidence=str(e),
            ))
        except Exception:
            pass

    if matches:
        # On construit une preuve lisible
        lignes = []
        total_comptes = 0
        for m in matches:
            try:
                pc = int(m.get("PwnCount", 0) or 0)
            except Exception:
                pc = 0
            total_comptes += pc
            dc = m.get("DataClasses") or []
            dc_txt = ", ".join([str(x) for x in dc][:6])
            lignes.append(
                "%s (domaine %s, date %s, %s comptes exposes ; donnees : %s)" % (
                    m.get("Title") or m.get("Name") or "?",
                    m.get("Domain"),
                    m.get("BreachDate") or "n/d",
                    "{:,}".format(pc).replace(",", " ") if pc else "n/d",
                    dc_txt or "n/d",
                )
            )
        noms = ", ".join([m.get("Title") or m.get("Name") or "?" for m in matches])
        try:
            findings.append(make_finding(
                id="breach_domain_found",
                category="Breach",
                title="Votre domaine figure dans une fuite de donnees connue (%d)" % len(matches),
                severity="eleve",
                status="fail",
                detail=(
                    "Le domaine '%s' correspond a %d fuite(s) recensee(s) par HIBP : %s. "
                    "Total de comptes exposes cumules : ~%s. "
                    "Cela signifie que des donnees liees a ce domaine (adresses e-mail "
                    "et parfois mots de passe) ont deja circule publiquement suite a un "
                    "piratage d'un service tiers." % (
                        clean, len(matches), noms,
                        "{:,}".format(total_comptes).replace(",", " ") if total_comptes else "n/d",
                    )
                ),
                patron=(
                    "Mauvaise nouvelle mais utile a savoir : le nom de domaine de votre "
                    "entreprise apparait dans %d fuite(s) de donnees deja connue(s) et "
                    "publique(s). Concretement, des adresses e-mail (et parfois des mots "
                    "de passe) associees a votre domaine ont fuite lors du piratage d'un "
                    "site externe. Le risque : si vos collaborateurs utilisent le meme "
                    "mot de passe au bureau que sur ces sites pirates, un attaquant peut "
                    "s'en servir pour entrer dans vos e-mails ou vos outils. "
                    "Ce n'est pas votre site qui a ete pirate, mais vos identifiants "
                    "circulent." % len(matches)
                ),
                reco=(
                    "1) Forcer le changement des mots de passe des comptes concernes. "
                    "2) Activer la double authentification (MFA) sur les e-mails et "
                    "outils cles. 3) Interdire la reutilisation des mots de passe pro "
                    "sur des sites externes (gestionnaire de mots de passe)."
                ),
                evidence=" | ".join(lignes)[:1500],
            ))
        except Exception:
            pass
    else:
        try:
            findings.append(make_finding(
                id="breach_domain_clean",
                category="Breach",
                title="Aucune fuite connue directement rattachee a votre domaine",
                severity="ok",
                status="pass",
                detail=(
                    "Le domaine '%s' (et son etiquette '%s') n'apparait pas dans le "
                    "champ 'Domain' des %d fuites publiques recensees par HIBP au moment "
                    "de l'audit. Note : cela ne couvre PAS les fuites ou les adresses de "
                    "vos employes apparaissent via un service tiers sans que le domaine "
                    "soit liste." % (clean, name, total)
                ),
                patron=(
                    "Bonne nouvelle : le nom de domaine de votre entreprise n'apparait "
                    "dans aucune des grandes fuites de donnees publiques connues a ce "
                    "jour. Attention, cela ne veut pas dire que zero collaborateur n'a "
                    "jamais ete touche : une adresse peut fuiter via un site externe. "
                    "C'est donc rassurant, mais la vigilance sur les mots de passe reste "
                    "de mise."
                ),
                reco=(
                    "Maintenir de bonnes habitudes : double authentification (MFA) sur "
                    "les e-mails et un gestionnaire de mots de passe pour eviter la "
                    "reutilisation."
                ),
                evidence="Domaine absent du champ 'Domain' des %d fuites HIBP." % total,
            ))
        except Exception:
            pass

    # --- 2) Finding info : ampleur mondiale des fuites -----------------------
    try:
        findings.append(make_finding(
            id="breach_world_total",
            category="Breach",
            title="Base mondiale des fuites : %d piratages recenses" % total,
            severity="info",
            status="info",
            detail=(
                "HIBP recense actuellement %d fuites de donnees publiques a l'echelle "
                "mondiale (LinkedIn, Adobe, Dropbox, Canva, etc.). Ces fuites contiennent "
                "des milliards d'identifiants qui circulent librement." % total
            ),
            patron=(
                "Pour donner l'echelle : il existe aujourd'hui %d piratages de sites "
                "connus et publics dans le monde, totalisant des milliards de mots de "
                "passe qui circulent librement. La vraie question pour votre entreprise "
                "est simple : vos employes reutilisent-ils leurs mots de passe "
                "professionnels sur des sites grand public (reseaux sociaux, boutiques, "
                "forums) ? Si oui, un seul de ces sites pirate suffit a exposer un acces "
                "a votre entreprise." % total
            ),
            reco=(
                "Deployer un gestionnaire de mots de passe et la double authentification "
                "(MFA) : c'est la mesure la plus rentable contre ce risque."
            ),
            evidence="%d entrees dans %s" % (total, HIBP_BREACHES_URL),
        ))
    except Exception:
        pass

    # --- 3) Finding info : verification compte-par-compte (option payante) ----
    try:
        findings.append(make_finding(
            id="breach_account_check_optional",
            category="Breach",
            title="Verification compte-par-compte disponible en option",
            severity="info",
            status="info",
            detail=(
                "La verification precise, adresse e-mail par adresse e-mail, via "
                "l'endpoint HIBP 'breachedaccount' necessite une cle API PAYANTE. Cet "
                "audit ne l'appelle pas (aucune depense). Avec une cle HIBP, on pourrait "
                "lister exactement quels comptes @%s ont fuite et dans quelles fuites." % clean
            ),
            patron=(
                "Version approfondie disponible : nous pouvons verifier, une par une, "
                "quelles adresses e-mail precises de votre entreprise ont fuite et dans "
                "quels piratages. Cette option necessite un petit abonnement payant "
                "(quelques euros) au service specialise ; elle n'est PAS activee ici pour "
                "ne rien vous facturer sans accord. A demander si vous voulez la liste "
                "nominative."
            ),
            reco=(
                "Option : souscrire une cle HIBP (~quelques $/mois) pour un rapport "
                "nominatif e-mail par e-mail. A activer uniquement sur demande."
            ),
            evidence="Endpoint payant non appele : /api/v3/breachedaccount (cle requise).",
        ))
    except Exception:
        pass

    if not findings:
        # Filet de securite : toujours renvoyer au moins un finding.
        try:
            findings.append(make_finding(
                id="breach_generic_info",
                category="Breach",
                title="Analyse des fuites de donnees",
                severity="info",
                status="info",
                detail="Aucun resultat exploitable produit par le module de fuites.",
                patron=(
                    "L'analyse des fuites de donnees n'a produit aucun resultat "
                    "exploitable cette fois. Relancez l'audit pour completer ce point."
                ),
                reco="Relancer l'audit.",
                evidence="",
            ))
        except Exception:
            pass

    return findings


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    clean, base = utils.normalize(target)
    print("=== modules/breach.py sur %s ===" % clean)
    results = scan(clean, base)
    print("Nombre de findings : %d\n" % len(results))
    for f in results:
        print("- [%s/%s] %s" % (f["severity"].upper(), f["status"], f["title"]))
        print("    PATRON : %s" % f["patron"][:160])
        if f["evidence"]:
            print("    PREUVE : %s" % f["evidence"][:160])
        print("")
