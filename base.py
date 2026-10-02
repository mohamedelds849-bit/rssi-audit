# -*- coding: utf-8 -*-
"""
base.py - Socle partage du RSSI virtuel PME.

Expose :
  - make_finding(...) : construit et VALIDE un finding (dict) selon le contrat de donnees.
  - SEVERITY_WEIGHTS  : poids de chaque gravite pour le scoring.

Un FINDING est un dict avec EXACTEMENT ces cles :
  id, category, title, severity, status, detail, patron, reco, evidence
"""

from typing import Dict

# Poids de gravite utilises par scoring.py
SEVERITY_WEIGHTS: Dict[str, int] = {
    "critique": 40,
    "eleve": 25,
    "moyen": 12,
    "faible": 5,
    "ok": 0,
    "info": 0,
}

# Valeurs autorisees (validation defensive)
VALID_CATEGORIES = {"SSL", "Headers", "Email", "Breach", "CVE", "General"}
VALID_SEVERITIES = set(SEVERITY_WEIGHTS.keys())
VALID_STATUSES = {"fail", "warn", "pass", "info"}

# Ordre exact des cles du contrat
FINDING_KEYS = ("id", "category", "title", "severity", "status",
                "detail", "patron", "reco", "evidence")


def make_finding(id: str, category: str, title: str, severity: str, status: str,
                 detail: str, patron: str, reco: str, evidence: str = "") -> Dict[str, str]:
    """
    Construit un finding valide.

    Leve ValueError avec un message CLAIR si une cle est manquante/vide
    ou si severity/status/category ont une valeur hors contrat.
    """
    # Champs texte obligatoires (non vides)
    for name, value in (("id", id), ("category", category), ("title", title),
                        ("severity", severity), ("status", status),
                        ("detail", detail), ("patron", patron), ("reco", reco)):
        if value is None or (isinstance(value, str) and value.strip() == ""):
            raise ValueError(
                "make_finding: le champ obligatoire '%s' est manquant ou vide." % name
            )
        if not isinstance(value, str):
            raise ValueError(
                "make_finding: le champ '%s' doit etre une chaine (str), recu %s."
                % (name, type(value).__name__)
            )

    if evidence is None:
        evidence = ""
    if not isinstance(evidence, str):
        raise ValueError("make_finding: 'evidence' doit etre une chaine (str).")

    # Validation des valeurs controlees
    if category not in VALID_CATEGORIES:
        raise ValueError(
            "make_finding: category '%s' invalide. Attendu l'un de %s."
            % (category, sorted(VALID_CATEGORIES))
        )
    if severity not in VALID_SEVERITIES:
        raise ValueError(
            "make_finding: severity '%s' invalide. Attendu l'un de %s."
            % (severity, sorted(VALID_SEVERITIES))
        )
    if status not in VALID_STATUSES:
        raise ValueError(
            "make_finding: status '%s' invalide. Attendu l'un de %s."
            % (status, sorted(VALID_STATUSES))
        )

    finding = {
        "id": id,
        "category": category,
        "title": title,
        "severity": severity,
        "status": status,
        "detail": detail,
        "patron": patron,
        "reco": reco,
        "evidence": evidence,
    }

    # Garantie finale : toutes les cles du contrat sont presentes
    missing = [k for k in FINDING_KEYS if k not in finding]
    if missing:
        raise ValueError("make_finding: cles manquantes dans le finding : %s" % missing)

    return finding


if __name__ == "__main__":
    # Test 1 : finding valide
    f = make_finding(
        id="demo_ok",
        category="General",
        title="Test du socle",
        severity="faible",
        status="warn",
        detail="Ceci est un detail technique de demonstration.",
        patron="En clair : ceci prouve que la fabrique de constats fonctionne.",
        reco="Aucune action requise, c'est un test.",
        evidence="preuve-brute-exemple",
    )
    print("[OK] make_finding a produit un finding valide :")
    for k in FINDING_KEYS:
        print("   %-9s = %s" % (k, f[k]))

    assert set(f.keys()) == set(FINDING_KEYS), "Les cles ne correspondent pas au contrat"

    # Test 2 : la validation doit lever une erreur claire
    try:
        make_finding("x", "CATEGORIE_BIDON", "t", "faible", "warn", "d", "p", "r")
        print("[ERREUR] la validation aurait du lever une exception")
    except ValueError as e:
        print("[OK] validation category : %s" % e)

    try:
        make_finding("x", "SSL", "t", "gravissime", "warn", "d", "p", "r")
        print("[ERREUR] la validation aurait du lever une exception")
    except ValueError as e:
        print("[OK] validation severity : %s" % e)

    try:
        make_finding("x", "SSL", "t", "faible", "warn", "d", "", "r")
        print("[ERREUR] la validation aurait du lever une exception")
    except ValueError as e:
        print("[OK] validation champ vide : %s" % e)

    print("\nSEVERITY_WEIGHTS =", SEVERITY_WEIGHTS)
    print("\nbase.py : tout fonctionne.")
