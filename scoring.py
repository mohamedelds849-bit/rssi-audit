# -*- coding: utf-8 -*-
"""
scoring.py - Moteur de scoring du RSSI virtuel PME.

Expose :
  - compute_score(findings) -> dict
        {
          "score": int (0..100),
          "grade": "A".."F",
          "emoji": str (🟢 / 🟠 / 🔴),
          "counts": {severity: int}   # compteur par gravite
        }

Logique de calcul (contrat) :
  - On part de 100 points.
  - Pour chaque finding dont le status est "fail" ou "warn",
    on soustrait le poids SEVERITY_WEIGHTS[severity].
      * "fail" -> poids plein
      * "warn" -> moitie du poids (arrondi a l'entier le plus proche)
  - Le score est borne dans [0, 100].
  - Les status "pass" et "info" ne penalisent jamais.

Grade :
  >= 90 -> A
  >= 75 -> B
  >= 60 -> C
  >= 40 -> D
  >= 20 -> E
  sinon -> F

Emoji (par grade / palier de score) :
  A, B      -> 🟢 (bon)
  C, D      -> 🟠 (a surveiller)
  E, F      -> 🔴 (a traiter en priorite)
"""

from typing import Any, Dict, Iterable, Optional, Tuple

try:
    # Import normal quand scoring.py est utilise comme module du projet.
    from base import SEVERITY_WEIGHTS
except Exception:  # pragma: no cover - filet de securite si import different
    SEVERITY_WEIGHTS = {
        "critique": 40,
        "eleve": 25,
        "moyen": 12,
        "faible": 5,
        "ok": 0,
        "info": 0,
    }

# Gravites connues (sert a initialiser les compteurs a 0)
_ALL_SEVERITIES = ("critique", "eleve", "moyen", "faible", "ok", "info")

# Status qui declenchent une penalite
_PENALIZING_STATUSES = ("fail", "warn")


def _grade_for(score: int) -> Tuple[str, str]:
    """Retourne (grade, emoji) pour un score entier 0..100."""
    if score >= 90:
        return "A", "🟢"
    if score >= 75:
        return "B", "🟢"
    if score >= 60:
        return "C", "🟠"
    if score >= 40:
        return "D", "🟠"
    if score >= 20:
        return "E", "🔴"
    return "F", "🔴"


def compute_score(findings: Optional[Iterable[Any]]) -> Dict[str, Any]:
    """
    Calcule le score de securite a partir d'une liste de findings.

    Ne plante jamais : un finding mal forme est ignore pour la penalite
    (mais quand meme compte si sa severity est connue).

    Parametres
    ----------
    findings : list[dict]
        Liste de findings (voir base.make_finding).

    Retour
    ------
    dict : {"score", "grade", "emoji", "counts"}
    """
    # Compteurs par gravite, initialises a 0 pour toutes les gravites connues.
    counts = {sev: 0 for sev in _ALL_SEVERITIES}

    score = 100

    if not findings:
        findings = []

    for f in findings:
        # Robustesse : on ignore ce qui n'est pas un dict exploitable.
        if not isinstance(f, dict):
            continue

        severity = f.get("severity")
        status = f.get("status")

        # Comptage par gravite (meme pour pass/info).
        if severity in counts:
            counts[severity] += 1
        elif isinstance(severity, str) and severity:
            # Gravite inconnue : on l'ajoute au compteur sans planter.
            counts[severity] = counts.get(severity, 0) + 1

        # Penalite uniquement pour fail / warn.
        if status not in _PENALIZING_STATUSES:
            continue

        weight = SEVERITY_WEIGHTS.get(severity, 0)
        if status == "warn":
            # Moitie du poids, arrondi a l'entier le plus proche.
            weight = int(round(weight / 2.0))

        score -= weight

    # Bornage strict [0, 100]
    if score < 0:
        score = 0
    elif score > 100:
        score = 100

    grade, emoji = _grade_for(score)

    return {
        "score": int(score),
        "grade": grade,
        "emoji": emoji,
        "counts": counts,
    }


if __name__ == "__main__":
    # Console Windows : force UTF-8 pour pouvoir afficher les emojis 🟢🟠🔴.
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    # Jeu de test factice couvrant TOUTES les gravites et TOUS les status.
    fake_findings = [
        # --- fail (poids plein) ---
        {"severity": "critique", "status": "fail", "title": "Fuite mot de passe admin"},   # -40
        {"severity": "eleve",    "status": "fail", "title": "Chaine SSL incomplete"},        # -25
        {"severity": "moyen",    "status": "fail", "title": "En-tete HSTS absent"},          # -12
        {"severity": "faible",   "status": "fail", "title": "Cookie sans flag Secure"},      # -5
        # --- warn (moitie du poids) ---
        {"severity": "critique", "status": "warn", "title": "CVE potentielle non confirmee"},# -20
        {"severity": "eleve",    "status": "warn", "title": "SPF trop permissif"},           # -12 (round(12.5)=12)
        {"severity": "moyen",    "status": "warn", "title": "En-tete X-Frame partiel"},      # -6
        {"severity": "faible",   "status": "warn", "title": "Version serveur exposee"},      # -2 (round(2.5)=2)
        # --- pass / info / ok : ne penalisent pas ---
        {"severity": "ok",       "status": "pass", "title": "Certificat valide"},            # 0
        {"severity": "info",     "status": "info", "title": "Emetteur : Let's Encrypt"},     # 0
        {"severity": "faible",   "status": "pass", "title": "DNSSEC present"},               # 0
    ]

    # Somme attendue des penalites (round bancaire : round(12.5)=12, round(2.5)=2) :
    #   fail : 40 + 25 + 12 + 5      = 82
    #   warn : 20 + 12 + 6 + 2       = 40
    #   total                        = 122  -> 100 - 122 = -22 -> borne a 0
    result = compute_score(fake_findings)

    print("=" * 60)
    print("  TEST scoring.py - jeu de findings factices")
    print("=" * 60)
    print("Nombre de findings testes :", len(fake_findings))
    print()
    print("SCORE  : %d / 100" % result["score"])
    print("GRADE  : %s" % result["grade"])
    print("EMOJI  : %s" % result["emoji"])
    print("COUNTS : %s" % result["counts"])
    print()

    # Verification explicite du calcul (auto-test).
    assert result["score"] == 0, "Score attendu 0 (penalites > 100), obtenu %d" % result["score"]
    assert result["grade"] == "F", "Grade attendu F, obtenu %s" % result["grade"]

    # Second test : peu de findings legers -> score haut.
    light = [
        {"severity": "faible", "status": "warn", "title": "Petit avertissement"},  # -2 (round(2.5)=2, arrondi bancaire)
        {"severity": "moyen",  "status": "warn", "title": "Avertissement moyen"},   # -6
        {"severity": "ok",     "status": "pass", "title": "Tout va bien"},          # 0
    ]
    r2 = compute_score(light)
    # 100 - 2 - 6 = 92 -> A
    print("-" * 60)
    print("TEST 2 (site plutot sain) : score=%d grade=%s emoji=%s"
          % (r2["score"], r2["grade"], r2["emoji"]))
    assert r2["score"] == 92, "Score attendu 92, obtenu %d" % r2["score"]
    assert r2["grade"] == "A", "Grade attendu A, obtenu %s" % r2["grade"]

    # Troisieme test : liste vide -> 100 / A.
    r3 = compute_score([])
    print("TEST 3 (aucun finding) : score=%d grade=%s emoji=%s"
          % (r3["score"], r3["grade"], r3["emoji"]))
    assert r3["score"] == 100 and r3["grade"] == "A"

    print()
    print("[OK] scoring.py : tous les auto-tests passent.")
