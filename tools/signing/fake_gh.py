#!/usr/bin/env python3
"""NUR für den lokalen Trockenlauf: ahmt die gh-Aufrufe von artifact_signing.py nach (nur Environment-Schutz).

    gh api repos/<owner>/<repo>/environments/<name>                            → Inhalt von FAKE_GH_UMGEBUNG
    gh api repos/<owner>/<repo>/environments/<name>/deployment-branch-policies → Inhalt von FAKE_GH_ZWEIGE
Installer laufen nie über GitHub (kein Release, kein Asset); dafür gibt es die Ablage (fake_storage.py).
Umgebung: FAKE_GH_MODUS (ok | umgebung-fehlt), FAKE_GH_PROTOKOLL (JSON-Zeilen je Aufruf).
Kein Netz, kein Token: GH_TOKEN wird weder gelesen noch protokolliert.
"""
import json
import os
import sys


def _protokoll(argv):
    pfad = os.environ.get("FAKE_GH_PROTOKOLL")
    if pfad:
        with open(pfad, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"argv": argv}, ensure_ascii=False) + "\n")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    _protokoll(argv)
    modus = os.environ.get("FAKE_GH_MODUS") or "ok"
    if len(argv) == 2 and argv[0] == "api" and argv[1].startswith("repos/"):
        teile = argv[1].split("/")
        if teile[3:4] == ["environments"] and len(teile) in (5, 6):
            quelle = "FAKE_GH_ZWEIGE" if teile[5:6] == ["deployment-branch-policies"] else "FAKE_GH_UMGEBUNG"
            if modus == "umgebung-fehlt":
                print("HTTP 404: Not Found (Trockenlauf)", file=sys.stderr)
                return 1
            with open(os.environ[quelle], encoding="utf-8") as fh:
                sys.stdout.write(fh.read())
            return 0
    print("Trockenlauf-gh: unbekannter Aufruf", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
