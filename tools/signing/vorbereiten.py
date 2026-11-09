#!/usr/bin/env python3
"""Signaturlauf vorbereiten (lokal, freigebende Person): prüft einen gebauten Fernwartungs-Installer wie die Vorprüfung,
prüft den Qualitätsnachweis quality.json, legt lokale Kopien an und druckt die fertigen Befehle (curl zur privaten
Ablage, gh zum Starten und Verfolgen des Workflows) mit eingesetzten Werten.

Führt selbst keinen Befehl aus, liest kein Token und ändert nichts in der Ablage, auf GitHub oder in Azure.

    python3 tools/signing/vorbereiten.py <installer.exe> --quality <quality.json> --version 2026.11.1 --erstausrollung
    python3 tools/signing/vorbereiten.py <installer.exe> --quality <quality.json> --version 2026.11.2 --vorgaenger-id R-…

Transport nur über die Ablage https://cockpit.insight-it.de/api/signing/artifacts – kein GitHub-Release, kein
Installer als GitHub-Artefakt. Das Token SIGNING_STORAGE_TOKEN muss in der ausführenden Shell exportiert sein; die
gedruckten Befehle reichen es nur per printf (Shell-Builtin) über stdin an curl (-H @-), nie als Argument.

Hilfs-Unterbefehle für die gedruckten Befehle (lesen nur stdin/Dateien, kein Netz):
    manifest-pruefen <BUILD_ID> <SHA256_UNSIGNIERT> <SHA256_QUALITY>
                                                stdin: Manifest der Ablage → unsigned + quality wie hochgeladen
    laeufe-vorher <BUILD_ID>                    stdin: gh run list --json … → IDs schon vorhandener Läufe (oder -)
    lauf-id <BUILD_ID> <VORHER>                 stdin: gh run list --json … → genau eine NEUE Lauf-ID
    nachweis-pruefen <ordner> <repo> <LAUF> <BUILD_ID> <SHA256_UNSIGNIERT> <VERSION> <KANAL> <VORGAENGER_ID|->
                                                Nachweise = dieser Lauf + Dispatch-Werte + lokaler SHA-256
    ergebnis-pruefen <download> <bericht> <ziel> <SHA256_UNSIGNIERT>
                                                signierter Installer aus der Ablage → SHA-256/Größe = Bericht → <ziel>
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import artifact_signing as sig  # noqa: E402

WORKFLOW_DATEI = "sign-cockpit.yml"
WORKFLOW_NAME = "Fernwartungs-Installer signieren"      # name: im Workflow
LAUF_TITEL = "Installer signieren %s"                   # run-name: im Workflow (mit der Build-ID)
LAUF_FELDER = "databaseId,displayTitle,event,headBranch,workflowName"
ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
KEINE = "-"                                             # leere Menge / Erstausrollung auf der Kommandozeile
CURL = "curl --proto =https --tlsv1.2 -fsS"


def _id(wert, code, was):
    """Numerische GitHub-ID (int > 0 oder Ziffernfolge) als Text; sonst Abbruch."""
    if isinstance(wert, bool) or not isinstance(wert, (int, str)) or not ID_RE.match(str(wert)):
        raise sig.SigningError(code, "%s ist keine gültige ID: %r" % (was, str(wert)[:40]))
    return str(wert)


def _pruefe_build_id(build_id):
    if not isinstance(build_id, str) or not sig.BUILD_ID_RE.match(build_id):
        raise sig.SigningError("eingabe_build_id", "Build-ID muss JJJJMMTT-HHMMSS sein, erhalten %r" % str(build_id)[:40])


def _passende_laeufe(laeufe, build_id):
    """IDs aller Läufe „Installer signieren <BUILD_ID>“ (Workflow-Name, workflow_dispatch, Zweig main)."""
    _pruefe_build_id(build_id)
    if not isinstance(laeufe, list):
        raise sig.SigningError("lauf_liste", "Antwort von gh run list ist keine Liste")
    titel = LAUF_TITEL % build_id
    ids = set()
    for eintrag in laeufe:
        if not isinstance(eintrag, dict):
            raise sig.SigningError("lauf_liste", "Antwort von gh run list enthält Unerwartetes")
        if (eintrag.get("displayTitle"), eintrag.get("event"), eintrag.get("headBranch"), eintrag.get("workflowName")) \
                == (titel, "workflow_dispatch", sig.ZWEIG, WORKFLOW_NAME):
            ids.add(_id(eintrag.get("databaseId"), "lauf_liste", "Lauf-ID"))
    return ids


def laeufe_vorher(laeufe, build_id):
    """Schnappschuss VOR dem Start: schon vorhandene Läufe dieser Build-ID (erneuter Dispatch desselben Builds)."""
    return _passende_laeufe(laeufe, build_id)


def lauf_aufloesen(laeufe, build_id, vorher=()):
    """Genau einen NEUEN Lauf aus `gh run list --json databaseId,displayTitle,event,headBranch,workflowName` bestimmen:
    Workflow-Name, workflow_dispatch, Zweig main und Titel „Installer signieren <BUILD_ID>“ (run-name), ohne die vor
    dem Start vorhandenen Läufe (`vorher`). Kein Treffer oder mehrere → Abbruch (nie „der neueste“, nie ein älterer)."""
    vorher = {_id(v, "lauf_liste", "Lauf-ID (vorher)") for v in vorher}
    ids = _passende_laeufe(laeufe, build_id) - vorher
    titel = LAUF_TITEL % build_id
    if not ids:
        raise sig.SigningError("lauf_fehlt", "Kein neuer Lauf „%s“ (workflow_dispatch, main%s) gefunden – ggf. in einigen "
                                             "Sekunden wiederholen" % (titel, ", ohne %d ältere" % len(vorher) if vorher else ""))
    if len(ids) > 1:
        raise sig.SigningError("lauf_mehrdeutig", "Mehrere neue Läufe „%s“: %s – den gemeinten Lauf im Browser prüfen und "
                                                  "LAUF=<id> selbst setzen" % (titel, ", ".join(sorted(ids, key=int))))
    return ids.pop()


def _pruefe_sha(sha256_unsigniert):
    if not isinstance(sha256_unsigniert, str) or not sig.SHA256_RE.match(sha256_unsigniert):
        raise sig.SigningError("eingabe_sha256", "SHA-256 muss aus 64 Hex-Zeichen bestehen")
    return sha256_unsigniert


def manifest_pruefen(manifest, build_id, sha256_unsigniert, sha256_quality):
    """Nach dem Upload: Ablage enthält genau den lokal geprüften Installer und Qualitätsnachweis, noch kein signed."""
    _pruefe_build_id(build_id)
    _pruefe_sha(sha256_unsigniert)
    _pruefe_sha(sha256_quality)
    sig.pruefe_manifest(manifest, build_id, "unsigned", sha256_unsigniert, abweichung_code="ablage_abweichung")
    sig.pruefe_manifest(manifest, build_id, "quality", sha256_quality, fehlt_code="quality_fehlt",
                        abweichung_code="ablage_abweichung")
    if any(isinstance(a, dict) and a.get("kind") == "signed" for a in manifest["artifacts"]):
        raise sig.SigningError("signiert_vorhanden", "Ablage enthält für %s schon einen signierten Installer" % build_id)
    return manifest


def pruefe_bericht(bericht, build_id, sha256_unsigniert):
    """signatur-bericht.json aus dem Nachweis-Artefakt: echter (kein Trockenlauf-)Bericht mit geprüfter Ablage, für genau
    den lokal geprüften unsignierten Installer (SHA-256 aus vorbereiten)."""
    _pruefe_sha(sha256_unsigniert)
    if build_id is None and isinstance(bericht, dict):
        build_id = bericht.get("build_id")
    _pruefe_build_id(build_id)
    ablage = bericht.get("ablage") if isinstance(bericht, dict) else None
    ok = (isinstance(bericht, dict) and bericht.get("format") == sig.BERICHT_FORMAT and bericht.get("build_id") == build_id
          and bericht.get("asset") == sig.asset_name(build_id) and bericht.get("trockenlauf") is False
          and isinstance(bericht.get("sha256_signiert"), str) and sig.SHA256_RE.match(bericht["sha256_signiert"])
          and isinstance(bericht.get("groesse_signiert"), int) and not isinstance(bericht.get("groesse_signiert"), bool)
          and 0 < bericht["groesse_signiert"] <= sig.MAX_GROESSE
          and isinstance(ablage, dict) and ablage.get("build_id") == build_id and ablage.get("kind") == "signed"
          and ablage.get("sha256") == bericht["sha256_signiert"] and ablage.get("groesse") == bericht["groesse_signiert"]
          and isinstance(bericht.get("qualitaet"), dict) and bericht["qualitaet"].get("bestanden") is True)
    if not ok:
        raise sig.SigningError("nachweis_ungueltig", "signatur-bericht.json passt nicht (Build-ID, Datei, Trockenlauf, "
                                                     "SHA-256, Qualität oder geprüfte Ablage fehlt)")
    if bericht.get("sha256_unsigniert") != sha256_unsigniert:
        raise sig.SigningError("nachweis_abweichung", "Signaturbericht gehört zu einem anderen unsignierten Installer "
                                                      "(SHA-256 ≠ lokal geprüfter Build) – älterer Lauf derselben Build-ID?")
    return bericht


def nachweis_pruefen(ordner, repo, lauf_id, erwartung):
    """Nachweis-Artefakt eines Laufs an genau diesen Lauf, den lokal geprüften Build und die Dispatch-Werte binden:
    signatur-bericht.json (Lauf-URL = <repo>/actions/runs/<LAUF>), release-metadata.json (Version, Kanal, Vorgänger,
    Erstausrollung, Artefakt = signierter Installer), signatur-nachweis.json (gueltig, gleicher SHA-256)."""
    lauf_id = _id(lauf_id, "lauf_liste", "Lauf-ID")
    if not sig.REPO_RE.match(repo or ""):
        raise sig.SigningError("eingabe_repo", "Repository muss owner/repo sein")
    e = erwartung
    _pruefe_build_id(e.get("build_id"))
    dateien = {}
    for name in sig.NACHWEIS_DATEIEN:
        pfad = os.path.join(ordner, name)
        if not os.path.isfile(pfad):
            raise sig.SigningError("nachweis_fehlt", "%s fehlt im Nachweis-Artefakt" % name)
        dateien[name] = _lies_json(pfad, "nachweis_ungueltig", name)
    release, nachweis, bericht = (dateien[n] for n in sig.NACHWEIS_DATEIEN)
    pruefe_bericht(bericht, e["build_id"], e.get("sha256"))
    lauf_url = bericht.get("lauf_url")
    if not isinstance(lauf_url, str) or not lauf_url or not sig.GIT_SHA_RE.match(str(bericht.get("git_sha"))):
        raise sig.SigningError("nachweis_ungueltig", "Signaturbericht ohne Lauf-URL oder Commit")
    if not re.fullmatch(r"https://[^/\s]+/%s/actions/runs/%s/attempts/[1-9][0-9]{0,4}" % (re.escape(repo), lauf_id), lauf_url,
                        re.I):
        raise sig.SigningError("nachweis_abweichung", "Nachweis stammt nicht aus Lauf %s von %s" % (lauf_id, repo))
    try:
        sig.pruefe_release_body(release)
        sig.pruefe_nachweis_body(nachweis)
    except (sig.SigningError, KeyError, TypeError, AttributeError):
        raise sig.SigningError("nachweis_ungueltig", "release-metadata.json bzw. signatur-nachweis.json entspricht nicht "
                                                     "dem Schema des Qualitäts-Gates") from None
    if nachweis["status"] != "gueltig" or str(release["notiz"]).startswith("TROCKENLAUF"):
        raise sig.SigningError("nachweis_ungueltig", "Nachweis ist nicht „gueltig“ oder stammt aus einem Trockenlauf")
    soll = {"version": e.get("version"), "build_id": e["build_id"], "kanal": e.get("kanal"),
            "vorgaenger_id": e.get("vorgaenger_id"), "erstausrollung": e.get("erstausrollung"),
            "artefakte": [{"name": bericht["asset"], "sha256": bericht["sha256_signiert"],
                           "groesse": bericht["groesse_signiert"]}]}
    abweichend = [k for k, v in soll.items() if release.get(k) != v]
    if release.get("git_sha") != bericht["git_sha"]:
        abweichend.append("git_sha")
    if (nachweis["artefakt"], nachweis["sha256"], nachweis["lauf_url"]) != (bericht["asset"], bericht["sha256_signiert"],
                                                                           lauf_url):
        abweichend.append("signatur-nachweis")
    if abweichend:
        raise sig.SigningError("nachweis_abweichung", "Nachweis passt nicht zu den Werten dieses Starts: %s"
                               % ", ".join(abweichend))
    return bericht


def ergebnis_pruefen(download, bericht, ziel, sha256_unsigniert):
    """Signierten Installer aus der Ablage prüfen: Bericht gehört zum lokal geprüften Build, Größe und SHA-256 =
    Signaturbericht (= im Lauf geprüfte Ablage), NSIS/Build-ID, Signatur vorhanden. Nur dann <ziel>/<datei> schreiben."""
    pruefe_bericht(bericht, None, sha256_unsigniert)
    name, groesse = bericht["asset"], bericht["groesse_signiert"]
    with open(download, "rb") as fh:
        data = fh.read(sig.MAX_GROESSE + 1)
    sha = hashlib.sha256(data).hexdigest()
    if len(data) != groesse or sha != bericht["sha256_signiert"]:
        raise sig.SigningError("sha256_abweichung", "Download (%d Bytes, SHA-256 %s…) ≠ Signaturbericht (%d Bytes, %s…)"
                               % (len(data), sha[:16], groesse, bericht["sha256_signiert"][:16]))
    layout, _werte = sig.pruefe_installer(data, bericht["build_id"])
    if not (layout["sec_va"] and layout["sec_size"]):
        raise sig.SigningError("signatur_fehlt", "Download enthält keine Signatur")
    pfad = os.path.join(ziel, name)
    sig._schreibe_atomar(pfad, data)
    return pfad


def repo_aus_git():
    try:
        url = subprocess.run(["git", "remote", "get-url", "origin"], capture_output=True, text=True, timeout=20,
                             cwd=os.path.dirname(os.path.dirname(HERE))).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$", url)
    return m.group(1) if m else None


def unsigniert_name(build_id):
    """Lokaler Name der unsignierten Kopie – nie verwechselbar mit dem signierten insight-fernwartung-<BID>.exe."""
    return sig.asset_name(build_id)[:-len(".exe")] + ".unsigniert.exe"


def quality_name(build_id):
    return "quality-%s.json" % build_id


def _kopiere_geprueft(quelle, ziel, sha):
    shutil.copyfile(quelle, ziel)
    with open(ziel, "rb") as fh:
        if hashlib.sha256(fh.read()).hexdigest() != sha:
            raise sig.SigningError("datei_veraendert", "Kopie %s weicht vom Original ab" % os.path.basename(ziel))


def vorbereiten(pfad, quality_pfad, version, kanal, vorgaenger_id, erstausrollung, ziel, repo):
    with open(pfad, "rb") as fh:
        data = fh.read(sig.MAX_GROESSE + 1)
    if len(data) > sig.MAX_GROESSE:
        raise sig.SigningError("datei_zu_gross", "Installer größer als 200 MiB (Grenze der Ablage)")
    layout = sig.pe_layout(data)
    werte = sig.version_strings(data, layout)
    build_id = werte.get("FileVersion", "")
    eingaben = sig.lese_eingaben({"SIGN_BUILD_ID": build_id, "SIGN_SHA256": hashlib.sha256(data).hexdigest(),
                                  "SIGN_VERSION": version, "SIGN_KANAL": kanal, "SIGN_VORGAENGER_ID": vorgaenger_id or "",
                                  "SIGN_ERSTAUSROLLUNG": "true" if erstausrollung else "false"})
    sig.pruefe_installer(data, eingaben["build_id"])
    if layout["sec_va"] or layout["sec_size"]:
        raise sig.SigningError("bereits_signiert", "Installer enthält schon eine Signatur – nur frische Builds")
    with open(quality_pfad, "rb") as fh:
        q_roh = fh.read(sig.MAX_QUALITY + 1)
    if len(q_roh) > sig.MAX_QUALITY:
        raise sig.SigningError("quality_ungueltig", "quality.json größer als 1 MiB")
    try:
        qualitaet = sig.pruefe_quality(json.loads(q_roh.decode("utf-8")), eingaben["build_id"])
    except (UnicodeDecodeError, ValueError):
        raise sig.SigningError("quality_ungueltig", "quality.json ist kein JSON") from None
    if not sig.REPO_RE.match(repo or ""):
        raise sig.SigningError("eingabe_repo", "Repository muss owner/repo sein")
    bid, sha_u, sha_q = eingaben["build_id"], eingaben["sha256"], hashlib.sha256(q_roh).hexdigest()
    kopie, q_kopie = os.path.join(ziel, unsigniert_name(bid)), os.path.join(ziel, quality_name(bid))
    for quelle, k in ((pfad, kopie), (quality_pfad, q_kopie)):
        if os.path.abspath(k) == os.path.abspath(quelle):
            raise sig.SigningError("ziel_gleich_quelle", "Quelle heißt wie die Arbeitskopie – das Aufräumen würde sie "
                                                         "löschen; Datei an anderem Ort ablegen oder --ziel ändern")
    os.makedirs(ziel, exist_ok=True)
    _kopiere_geprueft(pfad, kopie, sha_u)
    _kopiere_geprueft(quality_pfad, q_kopie, sha_q)
    q, r = shlex.quote, shlex.quote(repo)
    felder = ["-f build_id=%s" % bid, "-f sha256=%s" % sha_u, "-f version=%s" % q(version),
              "-f kanal=%s" % kanal] + (["-f vorgaenger_id=%s" % q(vorgaenger_id)] if vorgaenger_id else ["-f erstausrollung=true"])
    vb = "python3 %s" % q(os.path.abspath(__file__))
    erg = os.path.join(ziel, "signiert-" + bid)
    nachweis = os.path.join(erg, "signatur-nachweis-" + bid)
    bericht = os.path.join(nachweis, "signatur-bericht.json")
    roh = os.path.join(erg, "download.bin")
    build_url = "\"$ABLAGE/%s\"" % bid
    liste = "gh run list --repo %s --workflow %s --event workflow_dispatch --branch main --limit 50 --json %s" \
        % (r, WORKFLOW_DATEI, LAUF_FELDER)
    return eingaben, kopie, "\n".join([
        "# Geprüft: %s – Build-ID %s, SHA-256 %s, %d Bytes, NSIS, unsigniert" % (unsigniert_name(bid), bid, sha_u, len(data)),
        "# Geprüft: %s – bestanden, remote_e2e_fps %g, SHA-256 %s" % (quality_name(bid), qualitaet["remote_e2e_fps"], sha_q),
        "# Diese Werte vergleicht die freigebende Person mit der Zusammenfassung der Vorprüfung.",
        "# Befehle der Reihe nach in EINER bash ausführen (Shell bis Schritt 5 offen lassen) oder als Skript mit",
        "# bash -euo pipefail. Jeder Prüfbefehl endet bei Abweichung mit FEHLER [code] und Exit ≠ 0.",
        "# Voraussetzung: SIGNING_STORAGE_TOKEN ist in dieser Shell exportiert (aus dem Passwortmanager; nie in Dateien,",
        "# Verlauf oder Argumenten). Er geht nur per printf (Builtin) über stdin an curl (-H @-).",
        "",
        "# 0) Ablage, Token-Kopf und Aufräumfunktion. aufraeumen läuft beim Ende der Shell bzw. des Skripts automatisch",
        "#    (trap EXIT, auch unter set -e nach einem Fehler) und in Schritt 5 ausdrücklich; jeder Teil genau einmal.",
        "#    Ablage: nur ein eigener, nicht erfolgreich signierter Upload wird gelöscht. Nach einem grünen Lauf bleibt",
        "#    der Build bis zur Retention (7 Tage) liegen – signierte Artefakte nie von Hand löschen.",
        "ABLAGE=%s" % q(sig.STORAGE_BASIS),
        "HOCHGELADEN=0",
        "LAUF_OK=0",
        "ablage_kopf() { printf 'Authorization: Bearer %s\\n' \"${SIGNING_STORAGE_TOKEN:?}\"; }",
        "aufraeumen() {",
        "  trap - EXIT",
        "  if [ \"$HOCHGELADEN\" = 1 ] && [ \"$LAUF_OK\" != 1 ]; then",
        "    ablage_kopf | %s -X DELETE -H @- %s > /dev/null"
        " || echo \"WARNUNG: Build %s nicht aus der Ablage gelöscht – Retention entfernt ihn nach 7 Tagen\" >&2" % (CURL, build_url, bid),
        "  elif [ \"$LAUF_OK\" = 1 ]; then",
        "    echo \"HINWEIS: Build %s bleibt bis zur Retention (7 Tage) in der Ablage – nicht von Hand löschen\" >&2" % bid,
        "  fi",
        "  rm -f %s %s %s" % (q(kopie), q(q_kopie), q(roh)),
        "}",
        "trap aufraeumen EXIT",
        ": \"${SIGNING_STORAGE_TOKEN:?SIGNING_STORAGE_TOKEN in dieser Shell exportieren}\"",
        "",
        "# 1) Ablage erreichbar? Dann unsignierten Installer und Qualitätsnachweis hochladen (PUT, kein Überschreiben:",
        "#    409 = Build existiert schon – dann nichts löschen, sondern prüfen) und das Manifest gegenprüfen.",
        "%s %s > /dev/null" % (CURL, q(sig.STORAGE_HEALTH)),
        "ablage_kopf | %s -X PUT -H @- -H 'X-Artifact-SHA256: %s' -H 'Content-Type: application/octet-stream' "
        "--data-binary @%s \"$ABLAGE/%s/unsigned\" > /dev/null" % (CURL, sha_u, q(kopie), bid),
        "HOCHGELADEN=1",
        "ablage_kopf | %s -X PUT -H @- -H 'X-Artifact-SHA256: %s' -H 'Content-Type: application/json' "
        "--data-binary @%s \"$ABLAGE/%s/quality\" > /dev/null" % (CURL, sha_q, q(q_kopie), bid),
        "ablage_kopf | %s -H @- \"$ABLAGE/%s/manifest\" | %s manifest-pruefen %s %s %s" % (CURL, bid, vb, bid, sha_u, sha_q),
        "",
        "# 2) Vorhandene Läufe dieser Build-ID merken (nie wiederverwenden), dann Signaturlauf starten (nur von main)",
        "VORHER=\"$(%s | %s laeufe-vorher %s)\"" % (liste, vb, bid),
        "echo \"Ältere Läufe dieser Build-ID: ${VORHER:?Läufe vor dem Start nicht bestimmt}\"",
        "gh workflow run %s --repo %s --ref main %s" % (WORKFLOW_DATEI, r, " ".join(felder)),
        "",
        "# 3) NEUEN Lauf genau einmal bestimmen (Workflow, workflow_dispatch, main, Titel „%s“, nicht in VORHER)," % (
            LAUF_TITEL % bid),
        "#    verfolgen und im Environment release-signing freigeben. Kein/mehrere Treffer: Abbruch, LAUF nie raten.",
        "sleep 10",
        "LAUF=\"$(%s | %s lauf-id %s \"${VORHER:?Läufe vor dem Start nicht bestimmt}\")\"" % (liste, vb, bid),
        "echo \"Lauf ${LAUF:?Lauf nicht bestimmt}\"",
        "gh run watch --repo %s \"${LAUF:?Lauf nicht bestimmt}\" --exit-status" % r,
        "LAUF_OK=1",
        "",
        "# 4) Ergebnis laden: Nachweise (nur JSON) per gh run download und an diesen Lauf, den lokalen SHA-256 und die",
        "#    Werte dieses Starts binden; den signierten Installer aus der Ablage laden und gegen den Bericht prüfen.",
        "mkdir -p %s" % q(erg),
        "gh run download --repo %s \"${LAUF:?Lauf nicht bestimmt}\" --name signatur-nachweis-%s --dir %s"
        % (r, bid, q(nachweis)),
        "%s nachweis-pruefen %s %s \"${LAUF:?Lauf nicht bestimmt}\" %s %s %s %s %s"
        % (vb, q(nachweis), repo, bid, sha_u, q(version), kanal, q(vorgaenger_id) if vorgaenger_id else KEINE),
        "ablage_kopf | %s -H @- -o %s \"$ABLAGE/%s/signed\"" % (CURL, q(roh), bid),
        "%s ergebnis-pruefen %s %s %s %s" % (vb, q(roh), q(bericht), q(erg), sha_u),
        "",
        "# 5) Aufräumen – IMMER, unabhängig vom Ergebnis (läuft sonst spätestens beim Schließen der Shell): lokale",
        "#    unsignierte Kopie, Qualitätskopie und Download löschen; Ablage siehe Schritt 0.",
        "aufraeumen",
    ])


def _lies_json(datei, code, was):
    try:
        if hasattr(datei, "read"):
            return json.load(datei)
        with open(datei, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        raise sig.SigningError(code, "%s nicht lesbar oder kein JSON" % was) from None


def _menge(text):
    """Kommaliste von Lauf-IDs oder „-“ (keine)."""
    if text == KEINE:
        return set()
    return {_id(t, "lauf_liste", "Lauf-ID (vorher)") for t in text.split(",")}


HILFSBEFEHLE = {"manifest-pruefen": 3, "laeufe-vorher": 1, "lauf-id": 2, "nachweis-pruefen": 8, "ergebnis-pruefen": 4}


def hilfsbefehl(argv):
    """Hilfs-Unterbefehle (siehe Modulbeschreibung); Ausgabe nur die ID(s) bzw. eine Prüfzeile, Fehler → leeres stdout."""
    befehl, args = argv[0], argv[1:]
    soll = HILFSBEFEHLE[befehl]
    if len(args) != soll:
        print("Aufruf: vorbereiten.py %s (%d Argumente)" % (befehl, soll), file=sys.stderr)
        return 2
    try:
        if befehl == "manifest-pruefen":
            manifest_pruefen(_lies_json(sys.stdin, "manifest_ungueltig", "Manifest der Ablage"), *args)
            print("# Geprüft: Ablage enthält unsigned und quality von %s wie hochgeladen, noch kein signed" % args[0])
        elif befehl == "laeufe-vorher":
            ids = laeufe_vorher(_lies_json(sys.stdin, "lauf_liste", "Antwort von gh run list"), args[0])
            print(",".join(sorted(ids, key=int)) or KEINE)
        elif befehl == "lauf-id":
            vorher = _menge(args[1])
            print(lauf_aufloesen(_lies_json(sys.stdin, "lauf_liste", "Antwort von gh run list"), args[0], vorher))
        elif befehl == "nachweis-pruefen":
            ordner, repo, lauf_id, bid, sha_u, version, kanal, vorgaenger = args
            if vorgaenger != KEINE and not sig.RELEASE_ID_RE.match(vorgaenger):
                raise sig.SigningError("eingabe_vorgaenger", "Vorgänger-ID hat kein gültiges Format")
            erwartung = {"build_id": bid, "sha256": sha_u, "version": version, "kanal": kanal,
                         "vorgaenger_id": None if vorgaenger == KEINE else vorgaenger, "erstausrollung": vorgaenger == KEINE}
            b = nachweis_pruefen(ordner, repo, lauf_id, erwartung)
            print("# Geprüft: Nachweis aus Lauf %s – Build-ID %s, Version %s, Kanal %s, SHA-256 unsigniert %s…, signiert %s…"
                  % (lauf_id, bid, version, kanal, sha_u[:16], b["sha256_signiert"][:16]))
        else:
            bericht = _lies_json(args[1], "nachweis_ungueltig", "signatur-bericht.json")
            pfad = ergebnis_pruefen(args[0], bericht, args[2], args[3])
            print("# Geprüft: %s – SHA-256 %s, %d Bytes, signiert, = Signaturbericht"
                  % (pfad, bericht["sha256_signiert"], bericht["groesse_signiert"]))
    except sig.SigningError as exc:
        print("FEHLER [%s]: %s" % (exc.code, exc.meldung), file=sys.stderr)
        return 1
    except OSError as exc:
        print("FEHLER [datei_fehlt]: %s" % exc.__class__.__name__, file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in HILFSBEFEHLE:
        return hilfsbefehl(argv)
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("installer")
    ap.add_argument("--quality", required=True, help="quality.json des Builds (bestanden, build_id, remote_e2e_fps)")
    ap.add_argument("--version", required=True)
    ap.add_argument("--kanal", default="pilot", choices=sig.KANAELE)
    gruppe = ap.add_mutually_exclusive_group(required=True)
    gruppe.add_argument("--vorgaenger-id")
    gruppe.add_argument("--erstausrollung", action="store_true")
    ap.add_argument("--ziel", help="Ordner für die Kopien …unsigniert.exe und quality-<BUILD_ID>.json "
                                   "(Standard: Ordner des Installers)")
    ap.add_argument("--repo", help="owner/repo dieses Signatur-Repositorys (Standard: git remote origin)")
    args = ap.parse_args(argv)
    repo = args.repo or repo_aus_git()
    if not repo or not sig.REPO_RE.match(repo):
        ap.error("--repo owner/repo angeben (git remote origin nicht auswertbar)")
    try:
        _e, _kopie, befehle = vorbereiten(args.installer, args.quality, args.version, args.kanal, args.vorgaenger_id,
                                          args.erstausrollung, args.ziel or os.path.dirname(os.path.abspath(args.installer)),
                                          repo)
    except sig.SigningError as exc:
        print("FEHLER [%s]: %s" % (exc.code, exc.meldung), file=sys.stderr)
        return 1
    except OSError as exc:
        print("FEHLER [datei_fehlt]: %s" % exc.__class__.__name__, file=sys.stderr)
        return 1
    print(befehle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
