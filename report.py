# -*- coding: utf-8 -*-
"""
report.py - Generateur du rapport HTML "langage patron" du RSSI virtuel PME.

Expose :
  generate_report(domain, findings, score, history, out_dir) -> chemin_html

Le rapport est un fichier HTML 100% autonome (CSS inline, aucun CDN, aucune image
externe). Il est concu pour etre LU PAR UN PATRON DE PME qui n'y connait rien :
  - En-tete avec titre, domaine, date et gros badge de score colore (note /100 + grade).
  - Encart "En resume" en 2-3 phrases simples.
  - Compteurs par gravite en pastilles colorees.
  - Findings groupes par categorie ; pour chaque constat :
        titre + badge gravite -> explication PATRON (en avant) ->
        encart action "Que faire" -> detail technique repliable (<details>).
  - Ligne d'evolution si un historique est fourni.
  - Pied de page (mention audit non-intrusif + espace branding).

Ce module ne plante pas sur des donnees partielles : les cles manquantes d'un
finding sont tolerees (valeurs par defaut).
"""

import os
import html
import sys
from datetime import datetime
from typing import List, Optional


# ---------------------------------------------------------------------------
# Constantes de presentation
# ---------------------------------------------------------------------------

# Ordre d'affichage et libelles humains des categories
CATEGORY_ORDER = ["SSL", "Headers", "Email", "Breach", "CVE", "General"]
CATEGORY_LABELS = {
    "SSL": "Certificat & chiffrement (SSL/TLS)",
    "Headers": "En-tetes de securite du site",
    "Email": "Protection des emails (usurpation)",
    "Breach": "Fuites de donnees publiques",
    "CVE": "Failles connues des versions exposees (CVE)",
    "General": "Informations generales",
}
CATEGORY_ICONS = {
    "SSL": "\U0001F510",       # cadenas + cle
    "Headers": "\U0001F6E1",   # bouclier
    "Email": "\U0001F4E7",     # enveloppe
    "Breach": "\U0001F575",    # detective
    "CVE": "\U0001F41B",       # bug
    "General": "\U0001F4CB",   # presse-papier
}

# Couleurs et libelles par gravite
SEVERITY_ORDER = ["critique", "eleve", "moyen", "faible", "ok", "info"]
SEVERITY_LABELS = {
    "critique": "Critique",
    "eleve": "Eleve",
    "moyen": "Moyen",
    "faible": "Faible",
    "ok": "Bon point",
    "info": "Info",
}
SEVERITY_COLORS = {
    "critique": "#c0392b",  # rouge fort
    "eleve": "#e67e22",     # orange
    "moyen": "#f1c40f",     # jaune
    "faible": "#3498db",    # bleu
    "ok": "#27ae60",        # vert
    "info": "#7f8c8d",      # gris
}
# Couleur du texte a poser sur la couleur de gravite (contraste lisible)
SEVERITY_TEXT = {
    "critique": "#ffffff",
    "eleve": "#ffffff",
    "moyen": "#4d3b00",
    "faible": "#ffffff",
    "ok": "#ffffff",
    "info": "#ffffff",
}


# ---------------------------------------------------------------------------
# Petits helpers
# ---------------------------------------------------------------------------

def _esc(text):
    """Echappe le texte pour un rendu HTML sur."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text)


def _score_color(score):
    """Vert / orange / rouge selon le score."""
    try:
        s = int(score)
    except (TypeError, ValueError):
        s = 0
    if s >= 75:
        return "#27ae60"   # vert
    if s >= 50:
        return "#e67e22"   # orange
    return "#c0392b"       # rouge


def _score_word(score):
    """Un mot rassurant/mobilisateur selon le score."""
    try:
        s = int(score)
    except (TypeError, ValueError):
        s = 0
    if s >= 90:
        return "Excellent"
    if s >= 75:
        return "Bon niveau"
    if s >= 60:
        return "Correct, a ameliorer"
    if s >= 40:
        return "Fragile"
    if s >= 20:
        return "A risque"
    return "Tres expose"


def _fmt_date(dt=None):
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%d/%m/%Y a %Hh%M")


def _safe_get(finding, key, default=""):
    try:
        val = finding.get(key, default)
    except AttributeError:
        return default
    if val is None:
        return default
    return val


# ---------------------------------------------------------------------------
# Blocs de resume
# ---------------------------------------------------------------------------

def _build_counts(findings, score):
    """
    Retourne un dict {severite: nombre}. On utilise en priorite score['counts']
    (fourni par scoring.py) et on complete/recalcule depuis les findings au besoin.
    """
    counts = {s: 0 for s in SEVERITY_ORDER}

    # 1) depuis le score si disponible
    if isinstance(score, dict):
        c = score.get("counts")
        if isinstance(c, dict):
            for k, v in c.items():
                if k in counts:
                    try:
                        counts[k] = int(v)
                    except (TypeError, ValueError):
                        pass

    # 2) si le score n'a rien fourni, on compte nous-memes
    total_from_score = sum(counts.values())
    if total_from_score == 0 and findings:
        for f in findings:
            sev = _safe_get(f, "severity", "info")
            if sev in counts:
                counts[sev] += 1

    return counts


def _resume_phrases(findings, counts, score):
    """
    Construit 2-3 phrases simples de synthese, orientees action.
    """
    n_crit = counts.get("critique", 0)
    n_elev = counts.get("eleve", 0)
    n_moy = counts.get("moyen", 0)
    important = n_crit + n_elev

    # Score / mot
    s = 0
    if isinstance(score, dict):
        try:
            s = int(score.get("score", 0))
        except (TypeError, ValueError):
            s = 0

    phrases = []

    # Phrase 1 : etat general
    if important == 0 and n_moy == 0:
        phrases.append(
            "Bonne nouvelle : votre site ne presente aucun probleme important "
            "de securite dans cet audit."
        )
    elif important == 0:
        phrases.append(
            "Votre site n'a pas de faille grave, mais %d point%s d'attention "
            "meritent d'etre corriges quand vous le pourrez."
            % (n_moy, "s" if n_moy > 1 else "")
        )
    else:
        phrases.append(
            "Votre site a %d probleme%s important%s a corriger."
            % (important, "s" if important > 1 else "", "s" if important > 1 else "")
        )

    # Phrase 2 : le plus urgent (premier finding fail/critique-eleve)
    urgent = _find_most_urgent(findings)
    if urgent is not None:
        titre = _safe_get(urgent, "title", "un point de securite")
        phrases.append("Le plus urgent : %s." % titre.rstrip("."))
    elif important == 0 and n_moy == 0:
        phrases.append(
            "Continuez a surveiller regulierement : la securite se verifie "
            "dans le temps, pas une seule fois."
        )

    # Phrase 3 : cadrage rassurant + note
    phrases.append(
        "Note de securite globale : %d/100 (%s). "
        "Chaque point ci-dessous explique quoi faire, simplement."
        % (s, _score_word(s))
    )

    return phrases


def _severity_rank(sev):
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def _find_most_urgent(findings):
    """
    Le finding le plus urgent = statut fail/warn, gravite la plus forte.
    Renvoie None si rien d'actionnable.
    """
    if not findings:
        return None
    actionnables = [
        f for f in findings
        if _safe_get(f, "status", "info") in ("fail", "warn")
        and _safe_get(f, "severity", "info") in ("critique", "eleve", "moyen", "faible")
    ]
    if not actionnables:
        return None
    actionnables.sort(key=lambda f: _severity_rank(_safe_get(f, "severity", "info")))
    return actionnables[0]


# ---------------------------------------------------------------------------
# Rendu HTML : morceaux
# ---------------------------------------------------------------------------

def _render_pastilles(counts):
    """Pastilles colorees des compteurs par gravite (seulement celles qui comptent)."""
    parts = []
    # On montre toujours les 4 gravites d'action + les bons points s'il y en a
    show = ["critique", "eleve", "moyen", "faible"]
    if counts.get("ok", 0) > 0:
        show.append("ok")
    for sev in show:
        n = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        txt = SEVERITY_TEXT[sev]
        label = SEVERITY_LABELS[sev]
        dim = "" if n > 0 else "opacity:0.45;"
        parts.append(
            '<div class="pastille" style="background:%s;color:%s;%s">'
            '<span class="pastille-num">%d</span>'
            '<span class="pastille-lbl">%s</span>'
            "</div>" % (color, txt, dim, n, _esc(label))
        )
    return '<div class="pastilles">%s</div>' % "".join(parts)


def _render_evolution(history, current_score):
    """
    Ligne d'evolution si historique fourni.
    history = liste d'anciens enregistrements. On accepte plusieurs formats :
      - [{"score": 58, "date": "2026-09-01"}, ...]
      - [58, 64, ...]
    """
    if not history:
        return ""

    # Score courant
    cur = None
    if isinstance(current_score, dict):
        try:
            cur = int(current_score.get("score"))
        except (TypeError, ValueError):
            cur = None
    if cur is None:
        return ""

    # Dernier enregistrement de l'historique
    last = history[-1]
    prev_score = None
    prev_date = None
    if isinstance(last, dict):
        try:
            prev_score = int(last.get("score"))
        except (TypeError, ValueError):
            prev_score = None
        prev_date = last.get("date") or last.get("datetime") or last.get("timestamp")
    else:
        try:
            prev_score = int(last)
        except (TypeError, ValueError):
            prev_score = None

    if prev_score is None:
        return ""

    delta = cur - prev_score
    if delta > 0:
        color = "#27ae60"
        arrow = "↑"
        sign = "+%d" % delta
        mot = "en progres"
    elif delta < 0:
        color = "#c0392b"
        arrow = "↓"
        sign = "%d" % delta
        mot = "en recul"
    else:
        color = "#7f8c8d"
        arrow = "→"
        sign = "0"
        mot = "stable"

    date_part = ""
    if prev_date:
        # Rendre la date lisible si c'est de l'ISO
        d = str(prev_date)
        if "T" in d:
            d = d.split("T")[0]
        # ISO YYYY-MM-DD -> JJ/MM
        try:
            y, m, day = d[:10].split("-")
            d = "%s/%s" % (day, m)
        except ValueError:
            pass
        date_part = " (depuis le %s)" % _esc(d)

    return (
        '<div class="evolution" style="border-left:6px solid %s;">'
        '<span class="evo-arrow" style="color:%s;">%s</span> '
        "Score : <strong>%d</strong> &rarr; <strong>%d</strong> "
        '<span class="evo-delta" style="color:%s;">(%s pts, %s)</span>%s'
        "</div>"
        % (color, color, arrow, prev_score, cur, color, sign, mot, date_part)
    )


def _render_finding(finding):
    """Carte d'un constat unique."""
    sev = _safe_get(finding, "severity", "info")
    if sev not in SEVERITY_COLORS:
        sev = "info"
    color = SEVERITY_COLORS[sev]
    txt = SEVERITY_TEXT[sev]
    sev_label = SEVERITY_LABELS.get(sev, sev)

    title = _esc(_safe_get(finding, "title", "Constat"))
    patron = _esc(_safe_get(finding, "patron", ""))
    reco = _esc(_safe_get(finding, "reco", ""))
    detail = _esc(_safe_get(finding, "detail", ""))
    evidence = _esc(_safe_get(finding, "evidence", ""))
    status = _safe_get(finding, "status", "info")

    # Petit pictogramme selon statut
    status_icon = {
        "fail": "❌",   # croix
        "warn": "⚠",   # attention
        "pass": "✅",   # coche verte
        "info": "ℹ",   # info
    }.get(status, "ℹ")

    # Bloc "Que faire"
    reco_block = ""
    if reco:
        reco_block = (
            '<div class="reco">'
            '<div class="reco-lbl">\U0001F6E0 Que faire</div>'
            '<div class="reco-txt">%s</div>'
            "</div>" % reco
        )

    # Detail technique repliable
    tech_inner = ""
    if detail:
        tech_inner += '<p class="tech-detail">%s</p>' % detail
    if evidence:
        tech_inner += '<pre class="tech-evidence">%s</pre>' % evidence
    tech_block = ""
    if tech_inner:
        tech_block = (
            "<details class=\"tech\">"
            "<summary>Detail technique (pour votre informaticien)</summary>"
            "%s"
            "</details>" % tech_inner
        )

    patron_block = ""
    if patron:
        patron_block = '<p class="patron">%s</p>' % patron

    return (
        '<div class="finding" style="border-left:6px solid %s;">'
        '<div class="finding-head">'
        '<span class="finding-title">%s %s</span>'
        '<span class="badge" style="background:%s;color:%s;">%s</span>'
        "</div>"
        "%s%s%s"
        "</div>"
        % (color, status_icon, title, color, txt, _esc(sev_label),
           patron_block, reco_block, tech_block)
    )


def _render_category(cat, findings_in_cat):
    """Section d'une categorie."""
    label = CATEGORY_LABELS.get(cat, cat)
    icon = CATEGORY_ICONS.get(cat, "\U0001F4CC")

    # Tri : les plus graves d'abord
    ordered = sorted(
        findings_in_cat,
        key=lambda f: _severity_rank(_safe_get(f, "severity", "info")),
    )
    cards = "".join(_render_finding(f) for f in ordered)

    return (
        '<section class="category">'
        '<h2 class="cat-title">%s %s '
        '<span class="cat-count">%d constat%s</span></h2>'
        "%s"
        "</section>"
        % (icon, _esc(label), len(ordered),
           "s" if len(ordered) > 1 else "", cards)
    )


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def _css():
    return """
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #2c3e50;
  background: #eef2f5;
  line-height: 1.55;
}
.wrap { max-width: 900px; margin: 0 auto; padding: 24px 18px 60px; }
.header {
  background: linear-gradient(135deg, #1f3a5f 0%, #2c5282 100%);
  color: #fff;
  border-radius: 16px;
  padding: 28px 26px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  box-shadow: 0 8px 24px rgba(31,58,95,0.25);
}
.header .h-left { flex: 1 1 320px; }
.header h1 { margin: 0 0 6px; font-size: 24px; }
.header .domain { font-size: 18px; font-weight: 600; opacity: 0.95; }
.header .date { font-size: 13px; opacity: 0.8; margin-top: 4px; }
.score-badge {
  flex: 0 0 auto;
  width: 150px; height: 150px;
  border-radius: 50%;
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  color: #fff;
  box-shadow: 0 6px 18px rgba(0,0,0,0.25);
  border: 5px solid rgba(255,255,255,0.35);
}
.score-badge .num { font-size: 46px; font-weight: 800; line-height: 1; }
.score-badge .max { font-size: 15px; opacity: 0.9; }
.score-badge .grade { font-size: 15px; font-weight: 700; margin-top: 4px; letter-spacing:1px; }
.score-badge .word { font-size: 11px; margin-top: 2px; opacity: 0.95; text-align:center; padding:0 6px;}

.card {
  background: #fff;
  border-radius: 14px;
  padding: 20px 22px;
  margin-top: 20px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.06);
}
.resume h2 { margin: 0 0 10px; font-size: 19px; color:#1f3a5f; }
.resume p { margin: 6px 0; font-size: 16px; }
.resume .lead { font-size: 17px; font-weight: 600; }

.evolution {
  margin-top: 14px;
  background: #f7f9fb;
  padding: 10px 14px;
  border-radius: 8px;
  font-size: 15px;
}
.evo-arrow { font-size: 18px; font-weight: 800; }
.evo-delta { font-weight: 700; }

.pastilles { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 16px; }
.pastille {
  flex: 1 1 120px;
  min-width: 110px;
  border-radius: 12px;
  padding: 12px 10px;
  text-align: center;
}
.pastille-num { display:block; font-size: 30px; font-weight: 800; line-height: 1; }
.pastille-lbl { display:block; font-size: 13px; margin-top: 4px; font-weight:600; }

.category { margin-top: 26px; }
.cat-title {
  font-size: 18px;
  color: #1f3a5f;
  border-bottom: 2px solid #d7e0ea;
  padding-bottom: 8px;
  margin: 0 0 14px;
}
.cat-count { font-size: 13px; font-weight: 500; color:#7f8c8d; }

.finding {
  background: #fff;
  border-radius: 12px;
  padding: 16px 18px;
  margin-bottom: 14px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.06);
}
.finding-head {
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; flex-wrap: wrap; margin-bottom: 8px;
}
.finding-title { font-size: 17px; font-weight: 700; color:#2c3e50; }
.badge {
  font-size: 12px; font-weight: 700;
  padding: 4px 12px; border-radius: 999px;
  white-space: nowrap; text-transform: uppercase; letter-spacing: 0.5px;
}
.patron {
  font-size: 16px;
  margin: 8px 0 12px;
  color: #2c3e50;
}
.reco {
  background: #eafaf1;
  border: 1px solid #b8e6cd;
  border-radius: 10px;
  padding: 10px 14px;
  margin: 10px 0;
}
.reco-lbl { font-weight: 700; color: #1e7d47; font-size: 14px; margin-bottom: 3px; }
.reco-txt { font-size: 15px; color:#1e5631; }

.tech {
  margin-top: 8px;
  background: #f4f6f8;
  border-radius: 8px;
  padding: 6px 12px;
}
.tech summary {
  cursor: pointer;
  font-size: 13px;
  color: #5a6b7b;
  font-weight: 600;
  padding: 4px 0;
}
.tech-detail { font-size: 14px; color:#4a5866; margin: 8px 0; }
.tech-evidence {
  background: #1f2933;
  color: #cfe3f0;
  padding: 10px 12px;
  border-radius: 6px;
  font-size: 12px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
}

.footer {
  margin-top: 34px;
  text-align: center;
  color: #7f8c8d;
  font-size: 13px;
  border-top: 1px solid #d7e0ea;
  padding-top: 18px;
}
.footer .brand {
  margin-top: 10px;
  min-height: 34px;
  color: #b0bcc7;
  font-size: 12px;
}
@media (max-width: 560px) {
  .score-badge { width: 128px; height: 128px; }
  .score-badge .num { font-size: 38px; }
  .header h1 { font-size: 20px; }
}
"""


# ---------------------------------------------------------------------------
# Fonction principale
# ---------------------------------------------------------------------------

def generate_report(domain: str, findings: Optional[List[dict]], score: Optional[dict],
                    history: Optional[list], out_dir: str) -> str:
    """
    Genere un rapport HTML autonome et renvoie son chemin.

    Parametres
    ----------
    domain   : str  - domaine audite (ex "example.com")
    findings : list[dict] - liste de findings (contrat base.make_finding)
    score    : dict - {"score", "grade", "emoji", "counts"} (scoring.compute_score)
    history  : list - anciens enregistrements de score (peut etre None/[])
    out_dir  : str  - dossier de sortie (cree si absent)

    Retour
    ------
    str : chemin absolu du fichier HTML genere.
    """
    if findings is None:
        findings = []
    if not isinstance(score, dict):
        score = {"score": 0, "grade": "F", "emoji": "", "counts": {}}

    # Normalisations
    domain = str(domain or "domaine-inconnu")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        out_dir = os.getcwd()

    score_val = 0
    try:
        score_val = int(score.get("score", 0))
    except (TypeError, ValueError):
        score_val = 0
    grade = str(score.get("grade", "?"))
    emoji = str(score.get("emoji", ""))

    counts = _build_counts(findings, score)
    sc_color = _score_color(score_val)
    sc_word = _score_word(score_val)

    # --- Resume ---
    phrases = _resume_phrases(findings, counts, score)
    resume_html = ""
    for i, p in enumerate(phrases):
        cls = "lead" if i == 0 else ""
        resume_html += '<p class="%s">%s</p>' % (cls, _esc(p))

    # --- Evolution ---
    evolution_html = _render_evolution(history, score)

    # --- Pastilles ---
    pastilles_html = _render_pastilles(counts)

    # --- Findings groupes par categorie ---
    by_cat = {}
    for f in findings:
        cat = _safe_get(f, "category", "General")
        if cat not in CATEGORY_LABELS:
            cat = "General"
        by_cat.setdefault(cat, []).append(f)

    categories_html = ""
    for cat in CATEGORY_ORDER:
        if by_cat.get(cat):
            categories_html += _render_category(cat, by_cat[cat])
    # Categories inattendues eventuelles
    for cat, lst in by_cat.items():
        if cat not in CATEGORY_ORDER and lst:
            categories_html += _render_category(cat, lst)

    if not categories_html:
        categories_html = (
            '<section class="card"><p>Aucun constat a afficher '
            "pour cet audit.</p></section>"
        )

    date_str = _fmt_date()

    emoji_span = ""
    if emoji:
        emoji_span = '<div class="word">%s</div>' % _esc(emoji)

    doc = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport de securite - %(domain)s</title>
<style>%(css)s</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <div class="h-left">
      <h1>\U0001F6E1 Rapport de securite</h1>
      <div class="domain">%(domain)s</div>
      <div class="date">Audit realise le %(date)s</div>
    </div>
    <div class="score-badge" style="background:%(sc_color)s;">
      <div class="num">%(score)d</div>
      <div class="max">/ 100</div>
      <div class="grade">Note %(grade)s</div>
      <div class="word">%(sc_word)s</div>
      %(emoji)s
    </div>
  </div>

  <div class="card resume">
    <h2>\U0001F4DD En resume</h2>
    %(resume)s
    %(evolution)s
    %(pastilles)s
  </div>

  %(categories)s

  <div class="footer">
    Audit non-intrusif base uniquement sur des donnees publiques
    (certificat, en-tetes, DNS, fuites publiques, versions/CVE).<br>
    Aucune attaque n'a ete menee. Realise avec l'autorisation du proprietaire du domaine.
    <div class="brand"><!-- Espace branding : logo / cabinet / RSSI virtuel PME --></div>
  </div>

</div>
</body>
</html>
""" % {
        "domain": _esc(domain),
        "css": _css(),
        "date": _esc(date_str),
        "sc_color": sc_color,
        "score": score_val,
        "grade": _esc(grade),
        "sc_word": _esc(sc_word),
        "emoji": emoji_span,
        "resume": resume_html,
        "evolution": evolution_html,
        "pastilles": pastilles_html,
        "categories": categories_html,
    }

    safe_domain = "".join(c if (c.isalnum() or c in ("-", "_", ".")) else "_"
                          for c in domain)
    out_path = os.path.join(out_dir, "rapport_%s.html" % safe_domain)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)

    return os.path.abspath(out_path)


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        from base import make_finding
    except Exception:
        # Fabrique minimale de secours si base.py indisponible
        def make_finding(id, category, title, severity, status,
                         detail, patron, reco, evidence=""):
            return {
                "id": id, "category": category, "title": title,
                "severity": severity, "status": status, "detail": detail,
                "patron": patron, "reco": reco, "evidence": evidence,
            }

    demo_findings = [
        make_finding(
            id="ssl_expiry",
            category="SSL",
            title="Le certificat de securite expire bientot",
            severity="eleve",
            status="warn",
            detail="Le certificat TLS pour le domaine expire dans 9 jours "
                   "(valide jusqu'au 2026-09-25). Renouvellement automatique "
                   "non detecte.",
            patron="Le petit cadenas qui rassure vos clients va bientot "
                   "disparaitre. Si le certificat expire, les visiteurs verront "
                   "un gros message rouge \"site non securise\" et beaucoup "
                   "partiront aussitot.",
            reco="Demandez a votre hebergeur d'activer le renouvellement "
                 "automatique du certificat (Let's Encrypt le fait "
                 "gratuitement).",
            evidence="notAfter=2026-09-25 00:00:00 GMT",
        ),
        make_finding(
            id="ssl_ok_chain",
            category="SSL",
            title="Le chiffrement du site est bien configure",
            severity="ok",
            status="pass",
            detail="TLS 1.3 supporte, chaine de certificats complete, "
                   "aucun protocole obsolete (SSLv3/TLS1.0) accepte.",
            patron="Bonne nouvelle : les echanges entre vos clients et votre "
                   "site sont bien proteges. Rien a faire de ce cote.",
            reco="Aucune action requise. Continuez ainsi.",
            evidence="",
        ),
        make_finding(
            id="hsts_missing",
            category="Headers",
            title="Une protection anti-interception est absente (HSTS)",
            severity="moyen",
            status="fail",
            detail="En-tete Strict-Transport-Security absent des reponses HTTP.",
            patron="Il manque une petite regle de securite qui force les "
                   "navigateurs a toujours utiliser la version securisee de "
                   "votre site. Sans elle, un pirate sur un wifi public "
                   "pourrait tenter d'intercepter une connexion.",
            reco="Ajoutez l'en-tete Strict-Transport-Security dans la "
                 "configuration du serveur. Votre webmaster fait ca en 2 minutes.",
            evidence="GET / -> aucun header Strict-Transport-Security",
        ),
        make_finding(
            id="xfo_missing",
            category="Headers",
            title="Protection contre le detournement de clic manquante",
            severity="faible",
            status="warn",
            detail="X-Frame-Options / CSP frame-ancestors non definis.",
            patron="Votre site pourrait etre affiche dans une fausse page par "
                   "un escroc pour tromper vos visiteurs. Le risque est faible "
                   "mais facile a fermer.",
            reco="Ajoutez l'en-tete X-Frame-Options: SAMEORIGIN.",
            evidence="",
        ),
        make_finding(
            id="spf_missing",
            category="Email",
            title="Vos emails peuvent etre usurpes (SPF absent)",
            severity="critique",
            status="fail",
            detail="Aucun enregistrement SPF (TXT v=spf1) trouve pour le domaine.",
            patron="N'importe qui peut envoyer des emails en se faisant passer "
                   "pour vous (\"contact@votresociete.com\"). Vos clients "
                   "peuvent recevoir de fausses factures a votre nom : c'est "
                   "une porte grande ouverte a l'arnaque et cela abime votre "
                   "reputation.",
            reco="Ajoutez un enregistrement SPF chez votre fournisseur de nom "
                 "de domaine, puis DKIM et DMARC. Un prestataire email fait "
                 "cela rapidement.",
            evidence="dns TXT: (aucun enregistrement v=spf1)",
        ),
        make_finding(
            id="dmarc_none",
            category="Email",
            title="Aucune politique DMARC en place",
            severity="moyen",
            status="fail",
            detail="Enregistrement _dmarc absent.",
            patron="Meme si quelqu'un tente d'usurper votre adresse, vous "
                   "n'etes pas prevenu et rien ne bloque l'envoi. DMARC ferme "
                   "cette faille et vous donne des rapports.",
            reco="Publiez un enregistrement DMARC (commencez en mode "
                 "surveillance p=none, puis durcissez).",
            evidence="",
        ),
        make_finding(
            id="breach_email",
            category="Breach",
            title="Des adresses de l'entreprise apparaissent dans des fuites",
            severity="eleve",
            status="warn",
            detail="2 adresses professionnelles retrouvees dans des fuites "
                   "publiques anciennes (source: bases publiques agregees).",
            patron="Des mots de passe lies a vos adresses email ont deja fuite "
                   "par le passe sur d'autres sites. Si vos employes reutilisent "
                   "ces mots de passe, un intrus pourrait entrer.",
            reco="Faites changer les mots de passe concernes et activez la "
                 "double authentification (2FA) sur les comptes importants.",
            evidence="contact@exemple.com (fuite 2019), admin@exemple.com (2021)",
        ),
        make_finding(
            id="cve_wp",
            category="CVE",
            title="Une version de logiciel exposee a des failles connues",
            severity="eleve",
            status="fail",
            detail="Signature WordPress 6.1 detectee ; CVE-2023-XXXX "
                   "(gravite haute) applicable a cette branche.",
            patron="Le logiciel qui fait tourner votre site n'est pas a jour. "
                   "Des failles connues et publiques existent pour cette "
                   "version : des robots les cherchent automatiquement sur "
                   "internet.",
            reco="Mettez a jour le CMS et ses extensions vers la derniere "
                 "version. Planifiez des mises a jour regulieres.",
            evidence="meta generator: WordPress 6.1",
        ),
        make_finding(
            id="general_info",
            category="General",
            title="Audit realise sur des donnees publiques uniquement",
            severity="info",
            status="info",
            detail="Aucune intrusion, aucun test actif d'exploitation.",
            patron="Ce rapport observe votre site de l'exterieur, comme le "
                   "ferait un visiteur ou un curieux. Aucune attaque n'a ete "
                   "menee sur vos systemes.",
            reco="Refaites cet audit tous les 1 a 3 mois pour suivre les "
                 "progres.",
            evidence="",
        ),
    ]

    demo_score = {
        "score": 58,
        "grade": "D",
        "emoji": "\U0001F7E0",  # rond orange
        "counts": {"critique": 1, "eleve": 3, "moyen": 2, "faible": 1,
                   "ok": 1, "info": 1},
    }

    demo_history = [
        {"score": 52, "date": "2026-09-01"},
    ]

    # Dossier de sortie : 1er argument, sinon reports/ a cote du script.
    out_dir = (sys.argv[1] if len(sys.argv) > 1
               else os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"))
    os.makedirs(out_dir, exist_ok=True)

    path = generate_report(
        "example.com (DEMONSTRATION)",
        demo_findings, demo_score, demo_history, out_dir,
    )

    # On ecrit aussi une copie fixe _demo.html demandee
    demo_path = os.path.join(out_dir, "_demo.html")
    with open(path, "r", encoding="utf-8") as src:
        content = src.read()
    with open(demo_path, "w", encoding="utf-8") as dst:
        dst.write(content)

    size = os.path.getsize(demo_path)
    print("[OK] Rapport de demonstration genere.")
    print("     Chemin principal : %s" % path)
    print("     Copie _demo.html : %s" % demo_path)
    print("     Taille           : %d octets (%.1f Ko)" % (size, size / 1024.0))

    # Verification simple des sections attendues
    checks = {
        "En-tete score": "score-badge" in content,
        "Encart En resume": "En resume" in content,
        "Pastilles gravite": "pastilles" in content,
        "Ligne evolution": "Score :" in content and "evolution" in content,
        "Categorie SSL": "SSL" in content or "Certificat" in content,
        "Bloc Que faire": "Que faire" in content,
        "Detail repliable": "<details" in content,
        "Pied de page": "non-intrusif" in content,
    }
    print("     Verification des sections :")
    for name, ok in checks.items():
        print("       [%s] %s" % ("OK" if ok else "MANQUE", name))
