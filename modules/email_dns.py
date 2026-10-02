# -*- coding: utf-8 -*-
"""
modules/email_dns.py - Scanner anti-usurpation d'email (SPF / DMARC / DKIM / MX).

Verifie, uniquement a partir de donnees DNS publiques (non-intrusif), si le
domaine est protege contre l'usurpation d'identite par email (spoofing) :

  - SPF   : existe-t-il un TXT 'v=spf1 ...' ? Est-il strict (-all) ou faible (~all/?all/absent) ?
  - DMARC : TXT sur '_dmarc.<domaine>', 'v=DMARC1' present ? policy p=none (faible) vs quarantine/reject (bon) ?
  - DKIM  : teste quelques selecteurs courants (<sel>._domainkey.<domaine>).
  - MX    : le domaine a-t-il des serveurs de messagerie ?

Contrat : expose scan(domain, base_url) -> list[dict] (findings via base.make_finding).
Ne plante JAMAIS : chaque check est protege par try/except et renvoie au moins un finding.
"""

import os
import re
import sys
import subprocess

# --- Import robuste de base.make_finding et des helpers utils ---------------
# Le module peut etre importe soit comme 'modules.email_dns', soit charge
# directement ; on garantit l'acces a la racine du projet.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from base import make_finding  # noqa: E402
import utils  # noqa: E402


# Selecteurs DKIM les plus repandus (Google Workspace, Microsoft 365,
# Mailchimp/Mandrill, SendGrid, Zoho, etc.)
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1"]


def _dns_records(domain, rtype):
    """
    Recupere des enregistrements DNS d'un type donne (ex: 'MX').
    Essaie dnspython, sinon fallback 'nslookup -type=<rtype>'.
    Retourne une liste de chaines. Ne leve jamais.
    """
    domain = (domain or "").strip()
    if not domain:
        return []

    # 1) dnspython
    try:
        import dns.resolver  # type: ignore
        try:
            answers = dns.resolver.resolve(domain, rtype)
            out = []
            for rdata in answers:
                out.append(str(rdata).strip())
            if out:
                return out
        except Exception:
            pass
    except Exception:
        pass

    # 2) Fallback nslookup
    for flag in ("-type=%s" % rtype, "-querytype=%s" % rtype):
        try:
            proc = subprocess.run(
                ["nslookup", flag, domain],
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            recs = _parse_nslookup_generic(output, rtype)
            if recs:
                return recs
        except Exception:
            continue
    return []


def _parse_nslookup_generic(output, rtype):
    """Parse la sortie nslookup pour MX (mail exchanger) ou autres types."""
    records = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if rtype.upper() == "MX":
            # Formats:
            #   domain  MX preference = 10, mail exchanger = mx1.host.com
            #   domain  mail exchanger = mx1.host.com
            m = re.search(r'mail exchanger\s*=\s*(\S+)', line, re.IGNORECASE)
            if m:
                pref = ""
                mp = re.search(r'preference\s*=\s*(\d+)', line, re.IGNORECASE)
                if mp:
                    pref = mp.group(1) + " "
                records.append((pref + m.group(1)).strip())
        else:
            # generique : lignes 'name = value' ou apres 'internet address'
            m = re.search(r'=\s*(.+)$', line)
            if m and "server" not in low and "address" not in low:
                records.append(m.group(1).strip())
    # dedoublonne
    seen = set()
    out = []
    for r in records:
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _find_spf(txt_records):
    """Retourne l'enregistrement SPF (v=spf1 ...) parmi les TXT, ou None."""
    for rec in txt_records:
        if rec and rec.lower().strip().startswith("v=spf1"):
            return rec
    return None


def _spf_qualifier(spf):
    """Determine le qualificateur 'all' du SPF : '-all', '~all', '?all', '+all' ou None."""
    if not spf:
        return None
    m = re.search(r'([-~?+])all\b', spf, re.IGNORECASE)
    if m:
        return m.group(1) + "all"
    if re.search(r'\ball\b', spf, re.IGNORECASE):
        return "all"  # 'all' sans qualificateur = '+all' implicite
    return None


def _find_dmarc(txt_records):
    """Retourne l'enregistrement DMARC (v=DMARC1 ...) parmi des TXT, ou None."""
    for rec in txt_records:
        if rec and rec.lower().replace(" ", "").startswith("v=dmarc1"):
            return rec
    return None


def _dmarc_policy(dmarc):
    """Extrait la policy 'p=' du DMARC ('none' | 'quarantine' | 'reject') ou None."""
    if not dmarc:
        return None
    m = re.search(r'\bp\s*=\s*([a-zA-Z]+)', dmarc)
    if m:
        return m.group(1).lower()
    return None


# ---------------------------------------------------------------------------
# Checks individuels (chacun renvoie exactement un finding, jamais d'exception)
# ---------------------------------------------------------------------------

def _check_spf(domain, txt_records):
    try:
        spf = _find_spf(txt_records)
        if spf is None:
            return make_finding(
                id="email_spf",
                category="Email",
                title="SPF absent (pas de barriere anti-usurpation d'email)",
                severity="eleve",
                status="fail",
                detail=("Aucun enregistrement TXT 'v=spf1' trouve pour %s. "
                        "Sans SPF, aucun serveur destinataire ne peut verifier "
                        "quels serveurs sont autorises a envoyer du courrier en "
                        "votre nom." % domain),
                patron=("Aujourd'hui, n'importe qui sur Internet peut envoyer des "
                        "emails en se faisant passer pour votre entreprise. Un "
                        "escroc pourrait ecrire a vos clients ou fournisseurs avec "
                        "votre adresse pour reclamer un paiement ou voler des "
                        "informations. Rien ne l'en empeche."),
                reco=("Publier un enregistrement SPF chez votre hebergeur DNS, ex : "
                      "'v=spf1 include:_spf.votre-hebergeur.com -all'. Listez tous "
                      "vos outils d'envoi (site, CRM, newsletter) puis terminez par "
                      "'-all' (strict)."),
                evidence="TXT sans v=spf1",
            )

        qual = _spf_qualifier(spf)
        if qual == "-all":
            return make_finding(
                id="email_spf",
                category="Email",
                title="SPF present et strict (-all)",
                severity="ok",
                status="pass",
                detail=("SPF trouve avec politique stricte '-all' : les emails "
                        "envoyes par des serveurs non autorises seront rejetes. "
                        "SPF: %s" % spf),
                patron=("C'est bien : vous avez une premiere barriere solide. Les "
                        "serveurs qui ne sont pas dans votre liste blanche ne "
                        "peuvent pas envoyer d'email en votre nom."),
                reco="Rien a corriger sur SPF. Verifiez juste qu'il couvre tous vos outils d'envoi.",
                evidence=spf,
            )
        elif qual in ("~all", "?all", "all", "+all", None):
            faible = {"~all": "softfail (~all)",
                      "?all": "neutre (?all)",
                      "all": "permissif (all sans qualificateur)",
                      "+all": "totalement permissif (+all)",
                      None: "sans terminaison 'all'"}[qual]
            return make_finding(
                id="email_spf",
                category="Email",
                title="SPF present mais trop permissif (%s)" % faible,
                severity="moyen",
                status="warn",
                detail=("SPF trouve mais en mode %s. En softfail/neutre, les emails "
                        "suspects sont juste 'marques' au lieu d'etre rejetes ; "
                        "beaucoup passent quand meme. SPF: %s" % (faible, spf)),
                patron=("Vous avez une barriere, mais elle est entrouverte. Un "
                        "faussaire qui usurpe votre adresse a de bonnes chances que "
                        "son email arrive quand meme dans la boite de vos clients. "
                        "Il faut fermer completement la porte."),
                reco=("Passer la fin de votre SPF de '~all' (ou '?all') a '-all' "
                      "APRES avoir verifie que tous vos vrais outils d'envoi y sont "
                      "listes, pour ne bloquer que les usurpateurs."),
                evidence=spf,
            )
    except Exception as e:
        return make_finding(
            id="email_spf",
            category="Email",
            title="SPF : verification impossible",
            severity="info",
            status="info",
            detail="Erreur lors de la verification SPF : %r" % e,
            patron=("Nous n'avons pas pu verifier automatiquement la protection SPF "
                    "de votre domaine. A controler manuellement."),
            reco="Verifier manuellement la presence d'un TXT 'v=spf1 ... -all'.",
            evidence="",
        )


def _check_dmarc(domain):
    try:
        dmarc_domain = "_dmarc." + domain
        txt = []
        try:
            txt = utils.dns_txt(dmarc_domain)
        except Exception:
            txt = []
        dmarc = _find_dmarc(txt)

        if dmarc is None:
            return make_finding(
                id="email_dmarc",
                category="Email",
                title="DMARC absent (aucune regle anti-usurpation appliquee)",
                severity="eleve",
                status="fail",
                detail=("Aucun enregistrement 'v=DMARC1' trouve sur %s. DMARC est "
                        "la regle qui dit aux boites mail quoi faire des emails qui "
                        "usurpent votre domaine (les rejeter, les mettre en spam) et "
                        "qui vous envoie des rapports d'abus." % dmarc_domain),
                patron=("C'est le point le plus grave cote email. Sans DMARC, meme "
                        "si un escroc envoie un faux email en votre nom, les boites "
                        "de reception de vos clients n'ont aucune consigne pour le "
                        "bloquer. Resultat : arnaque directe a vos clients et "
                        "fournisseurs, avec votre nom en signature."),
                reco=("Publier un TXT sur '_dmarc.%s'. Commencer en surveillance : "
                      "'v=DMARC1; p=none; rua=mailto:vous@%s' pour recevoir des "
                      "rapports, puis durcir vers 'p=quarantine' puis 'p=reject'."
                      % (domain, domain)),
                evidence="Aucun v=DMARC1 sur " + dmarc_domain,
            )

        policy = _dmarc_policy(dmarc)
        if policy in ("reject", "quarantine"):
            return make_finding(
                id="email_dmarc",
                category="Email",
                title="DMARC actif et protecteur (p=%s)" % policy,
                severity="ok",
                status="pass",
                detail=("DMARC trouve avec policy 'p=%s' : les emails usurpant votre "
                        "domaine seront %s. DMARC: %s"
                        % (policy,
                           "rejetes" if policy == "reject" else "mis en quarantaine/spam",
                           dmarc)),
                patron=("Tres bien : vous avez donne la consigne aux boites mail de "
                        "bloquer (ou mettre en spam) tout email qui tente de se faire "
                        "passer pour vous. Vos clients sont proteges."),
                reco=("Rien d'urgent. Si vous etes en 'quarantine', viser a terme "
                      "'p=reject' pour la protection maximale."),
                evidence=dmarc,
            )
        elif policy == "none":
            return make_finding(
                id="email_dmarc",
                category="Email",
                title="DMARC present mais inactif (p=none, mode surveillance)",
                severity="eleve",
                status="warn",
                detail=("DMARC trouve mais avec 'p=none' : c'est un mode observation. "
                        "Les emails usurpes ne sont NI rejetes NI mis en spam ; vous "
                        "recevez juste des rapports. DMARC: %s" % dmarc),
                patron=("Vous avez installe l'alarme mais vous ne l'avez pas armee. "
                        "Un escroc qui usurpe votre adresse passe encore. C'est une "
                        "etape de transition normale, mais il faut la depasser vite."),
                reco=("Une fois vos envois legitimes valides dans les rapports DMARC, "
                      "passer 'p=none' a 'p=quarantine' puis 'p=reject'."),
                evidence=dmarc,
            )
        else:
            return make_finding(
                id="email_dmarc",
                category="Email",
                title="DMARC present mais policy illisible",
                severity="moyen",
                status="warn",
                detail=("Enregistrement DMARC trouve mais sans balise 'p=' claire. "
                        "DMARC: %s" % dmarc),
                patron=("Vous avez une regle anti-usurpation, mais elle semble mal "
                        "formee : sa protection reelle est incertaine. A faire "
                        "verifier."),
                reco="Corriger l'enregistrement DMARC pour inclure une policy 'p=quarantine' ou 'p=reject'.",
                evidence=dmarc,
            )
    except Exception as e:
        return make_finding(
            id="email_dmarc",
            category="Email",
            title="DMARC : verification impossible",
            severity="info",
            status="info",
            detail="Erreur lors de la verification DMARC : %r" % e,
            patron=("Nous n'avons pas pu verifier la regle DMARC de votre domaine. "
                    "A controler manuellement."),
            reco="Verifier manuellement la presence d'un TXT 'v=DMARC1; p=...' sur _dmarc.<domaine>.",
            evidence="",
        )


def _check_dkim(domain):
    try:
        found = []
        for sel in _DKIM_SELECTORS:
            name = "%s._domainkey.%s" % (sel, domain)
            try:
                txt = utils.dns_txt(name)
            except Exception:
                txt = []
            for rec in txt:
                low = (rec or "").lower()
                if "v=dkim1" in low or "p=" in low or "k=rsa" in low:
                    found.append((sel, rec))
                    break

        if found:
            sels = ", ".join(s for s, _ in found)
            ev = " | ".join("%s: %s" % (s, r[:80]) for s, r in found)
            return make_finding(
                id="email_dkim",
                category="Email",
                title="DKIM detecte (selecteurs: %s)" % sels,
                severity="ok",
                status="pass",
                detail=("Au moins une cle DKIM publique a ete trouvee sur les "
                        "selecteurs testes (%s). DKIM signe cryptographiquement vos "
                        "emails pour prouver qu'ils viennent bien de vous." % sels),
                patron=("Bon point : vos emails portent une signature numerique qui "
                        "prouve qu'ils sont authentiques. Cela renforce la confiance "
                        "et evite qu'ils tombent en spam."),
                reco="Rien a faire. Verifiez juste que la signature couvre tous vos outils d'envoi.",
                evidence=ev,
            )
        else:
            return make_finding(
                id="email_dkim",
                category="Email",
                title="DKIM non detecte sur les selecteurs courants (selecteur inconnu)",
                severity="info",
                status="info",
                detail=("Aucune cle DKIM trouvee sur les selecteurs testes (%s). "
                        "IMPORTANT : le nom du selecteur DKIM est propre a chaque "
                        "fournisseur et peut etre quelconque ; l'absence ici ne "
                        "prouve PAS qu'il n'y a pas de DKIM, seulement qu'aucun "
                        "selecteur courant ne correspond." % ", ".join(_DKIM_SELECTORS)),
                patron=("Nous n'avons pas pu confirmer la signature numerique de vos "
                        "emails avec les noms les plus courants. Ce n'est pas "
                        "forcement un probleme : il faut connaitre le nom exact "
                        "utilise par votre fournisseur d'email pour verifier."),
                reco=("Demander a votre fournisseur d'email (ou dans son panneau "
                      "d'administration) d'activer/verifier DKIM et de vous donner le "
                      "nom du selecteur pour controle."),
                evidence="Selecteurs testes: " + ", ".join(_DKIM_SELECTORS),
            )
    except Exception as e:
        return make_finding(
            id="email_dkim",
            category="Email",
            title="DKIM : verification impossible",
            severity="info",
            status="info",
            detail="Erreur lors de la verification DKIM : %r" % e,
            patron="Nous n'avons pas pu tester la signature DKIM de vos emails.",
            reco="Verifier manuellement DKIM aupres de votre fournisseur d'email.",
            evidence="",
        )


def _check_mx(domain):
    try:
        mx = _dns_records(domain, "MX")
        if mx:
            ev = " | ".join(mx)
            return make_finding(
                id="email_mx",
                category="Email",
                title="Serveurs de messagerie (MX) presents",
                severity="info",
                status="info",
                detail=("%d serveur(s) MX trouve(s) : ce domaine recoit du courrier. "
                        "MX: %s" % (len(mx), ev)),
                patron=("Votre domaine est bien configure pour recevoir des emails "
                        "professionnels. C'est aussi pour cela qu'il est important de "
                        "le proteger contre l'usurpation (voir SPF et DMARC)."),
                reco=("Comme votre domaine sert a l'email, assurez-vous que SPF (-all) "
                      "et DMARC (p=reject/quarantine) sont bien en place."),
                evidence=ev,
            )
        else:
            return make_finding(
                id="email_mx",
                category="Email",
                title="Aucun serveur de messagerie (MX) detecte",
                severity="faible",
                status="warn",
                detail=("Aucun enregistrement MX trouve pour %s : le domaine ne "
                        "semble pas configure pour recevoir des emails (ou le DNS ne "
                        "l'a pas renvoye)." % domain),
                patron=("Votre domaine ne semble pas recevoir d'emails. Si c'est "
                        "voulu (site vitrine sans messagerie), pensez tout de meme a "
                        "publier SPF et DMARC en mode strict pour empecher qu'on "
                        "usurpe votre nom pour envoyer du courrier."),
                reco=("Si vous utilisez l'email sur ce domaine, verifier la config MX. "
                      "Sinon, publier un SPF '-all' et un DMARC 'p=reject' pour "
                      "verrouiller l'envoi au nom du domaine."),
                evidence="Aucun MX",
            )
    except Exception as e:
        return make_finding(
            id="email_mx",
            category="Email",
            title="MX : verification impossible",
            severity="info",
            status="info",
            detail="Erreur lors de la verification MX : %r" % e,
            patron="Nous n'avons pas pu determiner si votre domaine recoit des emails.",
            reco="Verifier manuellement les enregistrements MX du domaine.",
            evidence="",
        )


# ---------------------------------------------------------------------------
# Point d'entree du scanner
# ---------------------------------------------------------------------------

def scan(domain: str, base_url: str) -> list:
    """
    Lance tous les checks anti-usurpation d'email pour 'domain'.
    Retourne une liste de findings (jamais vide, ne plante jamais).
    'base_url' n'est pas utilise ici (checks purement DNS) mais fait partie du contrat.
    """
    findings = []

    # Recupere une seule fois les TXT de l'apex (SPF y vit)
    try:
        txt_records = utils.dns_txt(domain)
    except Exception:
        txt_records = []

    findings.append(_check_spf(domain, txt_records))
    findings.append(_check_dmarc(domain))
    findings.append(_check_dkim(domain))
    findings.append(_check_mx(domain))

    # Garantie : jamais vide
    if not findings:
        findings.append(make_finding(
            id="email_generic",
            category="Email",
            title="Analyse email indisponible",
            severity="info",
            status="info",
            detail="Aucun check email n'a pu s'executer.",
            patron="Nous n'avons pas pu analyser la protection email de votre domaine.",
            reco="Reessayer plus tard ou verifier manuellement SPF/DMARC/DKIM/MX.",
            evidence="",
        ))
    return findings


if __name__ == "__main__":
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    clean, base = utils.normalize(target)
    print("=== Scan Email/DNS anti-usurpation : %s ===\n" % clean)

    results = scan(clean, base)
    for f in results:
        print("[%s | %s] %s" % (f["status"].upper(), f["severity"], f["title"]))
        print("   TECHNIQUE : %s" % f["detail"])
        print("   PATRON    : %s" % f["patron"])
        print("   RECO      : %s" % f["reco"])
        if f["evidence"]:
            print("   PREUVE    : %s" % f["evidence"])
        print("")

    print("--- JSON brut (%d findings) ---" % len(results))
    print(json.dumps(results, ensure_ascii=False, indent=2))
