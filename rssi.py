# -*- coding: utf-8 -*-
"""
rssi.py - Orchestrateur / CLI du RSSI virtuel PME.

Usage :
    python rssi.py <domaine> [options]
    python rssi.py --help

Ce que fait ce script :
  1. Normalise et valide le domaine saisi (utils.normalize / utils.is_valid_domain).
  2. Decouvre DYNAMIQUEMENT tous les scanners du dossier modules/
     (chaque module expose scan(domain, base_url) -> list[dict]).
  3. Lance chaque scanner (isole : un scanner qui plante n'arrete pas l'audit).
  4. Agrege tous les findings.
  5. Calcule le score (scoring.compute_score).
  6. Charge / met a jour l'historique data/history_<domaine>.json
     (liste d'objets {date, score}) et calcule l'evolution.
  7. Genere le rapport HTML (report.generate_report) dans reports/.
  8. Affiche un resume console clair (score, grade, compteurs par gravite,
     top 3 problemes, chemin du rapport).

Audit 100% passif de donnees publiques. Aucune API payante.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
import sys
import traceback
from datetime import datetime
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# --- Racine projet & chemins (toujours absolus) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# On s'assure que la racine est dans sys.path pour importer base/utils/scoring
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import utils          # noqa: E402
import scoring        # noqa: E402
import report         # noqa: E402

__version__ = "1.1.0"

Finding = Dict[str, str]
ScanFn = Callable[[str, str], List[Finding]]

# Codes de sortie
EXIT_OK = 0
EXIT_INVALID_DOMAIN = 2
EXIT_NO_SCANNER = 3
EXIT_INTERRUPTED = 130


def _force_utf8_console() -> None:
    """Console Windows : force UTF-8 pour afficher emojis / accents sans planter."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass


# Ordre d'affichage / de gravite (du pire au meilleur)
SEVERITY_ORDER = ["critique", "eleve", "moyen", "faible", "ok", "info"]

# Poids pour trier le "top 3 problemes" (les status penalisants d'abord)
_SEV_RANK = {"critique": 5, "eleve": 4, "moyen": 3, "faible": 2, "ok": 1, "info": 0}


def discover_scanners(modules_dir: str = MODULES_DIR,
                      only: Optional[Sequence[str]] = None,
                      skip: Optional[Sequence[str]] = None) -> List[Tuple[str, ScanFn]]:
    """
    Decouvre dynamiquement tous les modules Python de ``modules_dir`` qui
    exposent une fonction ``scan(domain, base_url)``.

    Les fichiers commencant par ``_`` sont ignores. ``only`` / ``skip``
    permettent de filtrer par nom de module.

    Retourne une liste de tuples (nom_module, fonction_scan), triee par nom
    pour un ordre stable.
    """
    scanners: List[Tuple[str, ScanFn]] = []
    if not os.path.isdir(modules_dir):
        return scanners

    only_set = {o.strip() for o in only} if only else None
    skip_set = {s.strip() for s in skip} if skip else set()

    for fname in sorted(os.listdir(modules_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        mod_name = fname[:-3]
        if only_set is not None and mod_name not in only_set:
            continue
        if mod_name in skip_set:
            continue
        try:
            # Import via le package 'modules' pour que les imports internes marchent.
            if os.path.abspath(modules_dir) == os.path.abspath(MODULES_DIR):
                module = importlib.import_module("modules." + mod_name)
            else:
                raise ImportError("dossier de modules personnalise")
        except Exception:
            # Fallback : chargement direct par chemin de fichier.
            try:
                spec = importlib.util.spec_from_file_location(
                    "modules." + mod_name, os.path.join(modules_dir, fname)
                )
                module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
                spec.loader.exec_module(module)  # type: ignore[union-attr]
            except Exception as e:
                print("  [!] Impossible de charger le module %s (ignore) : %s" % (mod_name, e))
                continue

        scan_fn = getattr(module, "scan", None)
        if callable(scan_fn):
            scanners.append((mod_name, scan_fn))
        else:
            print("  [!] Module %s sans fonction scan() -> ignore." % mod_name)

    return scanners


def run_all_scanners(scanners: Sequence[Tuple[str, ScanFn]], domain: str,
                     base_url: str, verbose: bool = False) -> List[Finding]:
    """
    Execute chaque scanner de facon isolee. Un scanner qui leve une exception
    ne stoppe pas l'audit : on log et on continue.
    Retourne la liste agregee de tous les findings (dicts).
    """
    all_findings: List[Finding] = []
    for name, scan_fn in scanners:
        try:
            result = scan_fn(domain, base_url)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print("  [!] Le scanner '%s' a plante : %s" % (name, e))
            if verbose:
                traceback.print_exc()
            continue

        if not result:
            print("  [i] %-14s -> 0 finding" % name)
            continue

        count = 0
        for f in result:
            if isinstance(f, dict):
                all_findings.append(f)
                count += 1
        print("  [+] %-14s -> %d finding(s)" % (name, count))

    return all_findings


def history_path(domain: str, data_dir: str = DATA_DIR) -> str:
    """Chemin du fichier d'historique d'un domaine."""
    return os.path.join(data_dir, "history_%s.json" % domain)


def load_history(domain: str, data_dir: str = DATA_DIR) -> Tuple[list, str]:
    """Charge l'historique JSON (liste d'objets {date, score}). [] si absent/casse."""
    path = history_path(domain, data_dir)
    if not os.path.isfile(path):
        return [], path
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return data, path
    except Exception:
        pass
    return [], path


def save_history(history: list, path: str) -> bool:
    """Ecrit l'historique sur disque (cree le dossier au besoin)."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(history, fh, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print("  [!] Impossible d'ecrire l'historique : %s" % e)
        return False


def compute_evolution(history: list, new_score: int) -> Tuple[Optional[int], Optional[int]]:
    """
    A partir de l'historique (AVANT ajout du point courant), retourne
    (delta, dernier_score) ou (None, None) si pas de precedent.
    """
    if not history:
        return None, None
    # Dernier point valide avec un score numerique.
    for entry in reversed(history):
        if isinstance(entry, dict) and isinstance(entry.get("score"), (int, float)):
            prev = int(entry["score"])
            return int(new_score) - prev, prev
    return None, None


def top_problems(findings: Sequence[Finding], n: int = 3) -> List[Finding]:
    """Retourne les n findings les plus graves (status fail/warn), tries."""
    problems = [
        f for f in findings
        if isinstance(f, dict) and f.get("status") in ("fail", "warn")
    ]
    problems.sort(
        key=lambda f: (
            _SEV_RANK.get(f.get("severity"), 0),
            0 if f.get("status") == "fail" else -1,  # fail avant warn a gravite egale
        ),
        reverse=True,
    )
    return problems[:n]


def print_summary(domain: str, findings: Sequence[Finding], score: dict,
                  delta: Optional[int], prev_score: Optional[int],
                  report_path: str) -> None:
    """Affiche un resume console clair et lisible."""
    line = "=" * 64
    print("")
    print(line)
    print("  RSSI VIRTUEL PME - RESUME DE L'AUDIT")
    print(line)
    print("  Domaine        : %s" % domain)
    print("  Date           : %s" % datetime.now().strftime("%Y-%m-%d %H:%M"))
    print("  Findings total : %d" % len(findings))
    print("")
    print("  SCORE   : %s  %d / 100   (note %s)"
          % (score.get("emoji", ""), score.get("score", 0), score.get("grade", "?")))

    # Evolution
    if delta is None:
        print("  EVOLUTION : premier audit (aucun historique precedent)")
    elif delta > 0:
        print("  EVOLUTION : +%d points depuis le dernier audit (%d -> %d)"
              % (delta, prev_score, score.get("score", 0)))
    elif delta < 0:
        print("  EVOLUTION : %d points depuis le dernier audit (%d -> %d)"
              % (delta, prev_score, score.get("score", 0)))
    else:
        print("  EVOLUTION : stable (aucun changement de score : %d)" % prev_score)

    # Compteurs par gravite
    counts = score.get("counts", {}) or {}
    print("")
    print("  Repartition par gravite :")
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c:
            print("     - %-9s : %d" % (sev, c))

    # Top 3 problemes
    tops = top_problems(findings, 3)
    print("")
    if tops:
        print("  TOP 3 PROBLEMES A TRAITER :")
        for i, f in enumerate(tops, 1):
            print("     %d. [%s] %s"
                  % (i, f.get("severity", "?"), f.get("title", "(sans titre)")))
            reco = f.get("reco", "")
            if reco:
                print("        -> %s" % reco)
    else:
        print("  Aucun probleme penalisant detecte. Beau travail !")

    print("")
    print("  RAPPORT HTML   : %s" % report_path)
    print(line)
    print("")


def audit(domain_input: str,
          output_dir: str = REPORTS_DIR,
          data_dir: str = DATA_DIR,
          use_history: bool = True,
          json_path: Optional[str] = None,
          only: Optional[Sequence[str]] = None,
          skip: Optional[Sequence[str]] = None,
          verbose: bool = False) -> int:
    """Pipeline complet d'audit pour un domaine. Retourne un code de sortie int."""
    clean_domain, base_url = utils.normalize(domain_input)
    if not utils.is_valid_domain(clean_domain):
        print("Domaine invalide : %r (attendu : exemple.com)" % domain_input)
        return EXIT_INVALID_DOMAIN

    print("")
    print(">>> Audit passif de : %s  (%s)" % (clean_domain, base_url))
    print(">>> Decouverte des scanners dans %s ..." % MODULES_DIR)

    scanners = discover_scanners(only=only, skip=skip)
    if not scanners:
        print("  [!] Aucun scanner trouve dans modules/. Abandon.")
        return EXIT_NO_SCANNER
    print("  Scanners charges : %s" % ", ".join(n for n, _ in scanners))
    print("")
    print(">>> Execution des scanners ...")

    findings = run_all_scanners(scanners, clean_domain, base_url, verbose=verbose)

    # --- Scoring ---
    score = scoring.compute_score(findings)

    # --- Historique (AVANT ajout du point courant) ---
    history: list = []
    delta: Optional[int] = None
    prev_score: Optional[int] = None
    if use_history:
        history, hist_path = load_history(clean_domain, data_dir)
        delta, prev_score = compute_evolution(history, score.get("score", 0))
        history_for_report = list(history)  # anciens points uniquement
        history.append({
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": int(score.get("score", 0)),
            "grade": score.get("grade", "?"),
        })
        save_history(history, hist_path)
    else:
        history_for_report = []

    # --- Rapport HTML ---
    try:
        report_path = report.generate_report(
            clean_domain, findings, score, history_for_report, output_dir
        )
    except Exception as e:
        print("  [!] Erreur lors de la generation du rapport : %s" % e)
        if verbose:
            traceback.print_exc()
        report_path = "(non genere)"

    # --- Export JSON optionnel ---
    if json_path:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump({
                    "domain": clean_domain,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "tool_version": __version__,
                    "score": score,
                    "findings": findings,
                }, fh, ensure_ascii=False, indent=2)
            print("  [+] Export JSON : %s" % os.path.abspath(json_path))
        except Exception as e:
            print("  [!] Export JSON impossible : %s" % e)

    # --- Resume console ---
    print_summary(clean_domain, findings, score, delta, prev_score, report_path)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments de la CLI."""
    parser = argparse.ArgumentParser(
        prog="rssi.py",
        description=(
            "Passive external security audit for small businesses (SME). "
            "Checks SSL/TLS, HTTP security headers, SPF/DKIM/DMARC/MX, public "
            "breach data (HIBP) and CVEs matching exposed software versions (NVD). "
            "Produces a plain-language HTML report with a score out of 100. "
            "Only audit domains you own or are explicitly authorized to test."
        ),
        epilog="Example: python rssi.py example.com -o reports --json reports/example.json",
    )
    parser.add_argument("domain", nargs="?",
                        help="domain to audit (e.g. example.com or https://example.com/)")
    parser.add_argument("-o", "--output-dir", default=None,
                        help="directory for the HTML report (default: ./reports next to rssi.py)")
    parser.add_argument("--data-dir", default=None,
                        help="directory for score history files (default: ./data next to rssi.py)")
    parser.add_argument("--no-history", action="store_true",
                        help="do not read or write the score history")
    parser.add_argument("--json", dest="json_path", metavar="FILE",
                        help="also export the score + raw findings as JSON")
    parser.add_argument("--only", metavar="MODULES",
                        help="comma-separated list of scanners to run (e.g. ssl_headers,email_dns)")
    parser.add_argument("--skip", metavar="MODULES",
                        help="comma-separated list of scanners to skip (e.g. cve,breach)")
    parser.add_argument("--list-modules", action="store_true",
                        help="list discovered scanner modules and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print full tracebacks when a scanner fails")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def _split_csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Point d'entree CLI. ``argv`` exclut le nom du programme."""
    _force_utf8_console()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        for name, _ in discover_scanners():
            print(name)
        return EXIT_OK

    if not args.domain:
        parser.print_usage()
        print("error: a domain is required (see --help)")
        return EXIT_INVALID_DOMAIN

    try:
        return audit(
            args.domain,
            output_dir=args.output_dir or REPORTS_DIR,
            data_dir=args.data_dir or DATA_DIR,
            use_history=not args.no_history,
            json_path=args.json_path,
            only=_split_csv(args.only),
            skip=_split_csv(args.skip),
            verbose=args.verbose,
        )
    except KeyboardInterrupt:
        print("\n  [!] Audit interrompu par l'utilisateur.")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
