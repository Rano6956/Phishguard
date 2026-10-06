#!/usr/bin/env python3
"""Mesure la qualité de détection de PhishGuard sur un corpus étiqueté.

Arborescence attendue :
    <corpus>/phishing/...   emails de phishing (.eml ou .txt)
    <corpus>/legit/...      emails légitimes

    python evaluate.py samples/              # seuil 60 : « phishing probable »
    python evaluate.py samples/ --seuil 30   # compte aussi les « suspects » comme positifs
"""
import argparse
import sys
from pathlib import Path

from phishguard import PHISHING_AT, analyze_file


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpus", type=Path, help="dossier contenant phishing/ et legit/")
    ap.add_argument("--seuil", type=int, default=PHISHING_AT, help=f"score de bascule (défaut {PHISHING_AT})")
    args = ap.parse_args(argv)

    rows = []
    for label in ("phishing", "legit"):
        folder = args.corpus / label
        for path in sorted(folder.rglob("*")) if folder.is_dir() else []:
            if path.is_file() and path.suffix.lower() in (".eml", ".txt"):
                rows.append((path, label == "phishing", analyze_file(path).score))
    if not rows:
        print(f"Aucun email trouvé dans {args.corpus}/phishing ni {args.corpus}/legit.", file=sys.stderr)
        return 2

    tp = sum(1 for _, y, s in rows if y and s >= args.seuil)
    fn = sum(1 for _, y, s in rows if y and s < args.seuil)
    fp = sum(1 for _, y, s in rows if not y and s >= args.seuil)
    tn = len(rows) - tp - fn - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    print(f"Corpus : {len(rows)} emails ({tp + fn} phishing, {fp + tn} légitimes), seuil {args.seuil}")
    print(f"  Vrais positifs {tp:>4}   Faux négatifs {fn:>4}")
    print(f"  Faux positifs  {fp:>4}   Vrais négatifs {tn:>4}")
    print(f"  Précision {precision:.0%}   Rappel {recall:.0%}   F1 {f1:.2f}")
    errors = [(p, y, s) for p, y, s in rows if (s >= args.seuil) != y]
    if errors:
        print("Erreurs de classement :")
        for path, is_phish, score in errors:
            kind = "phishing manqué" if is_phish else "faux positif"
            print(f"  {kind:<16} score {score:>3}  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
