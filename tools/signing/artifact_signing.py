#!/usr/bin/env python3
"""Signaturpfad für den Fernwartungs-Installer (NSIS) mit Microsoft Artifact Signing.

Wird vom Workflow .github/workflows/sign-cockpit.yml aufgerufen und lokal vom Trockenlauf
(tools/signing/trockenlauf.py) mit Fake-Werkzeugen durchgespielt. Diese Helfer nutzen nur die
Python-Standardbibliothek: Im Signier-Job läuft kein pip und kein eigener nachinstallierter Drittcode.
Die Microsoft-Signing-Action installiert dagegen zur Laufzeit ihr PowerShell-Modul und NuGet-Pakete
(versioniert, nicht per Hash gepinnt); diese Ausnahme ist im Runbook dokumentiert.

Transport: Installer und Qualitätsnachweis liegen nie in GitHub (kein Release, kein Installer-Artefakt), sondern in der
privaten Signatur-Artefaktablage (HTTPS, Vertrag siehe docs/release-signing.md, Abschnitt „Artefaktablage“):
    GET/PUT  <ABLAGE>/<BUILD_ID>/{unsigned,signed,quality}    GET <ABLAGE>/<BUILD_ID>/manifest
Authentifizierung ausschließlich Authorization: Bearer <Repo-Secret SIGNING_STORAGE_TOKEN>. HTTP läuft über einen
injizierbaren Transport: produktiv HttpsTransport (nur https://cockpit.insight-it.de, keine Weiterleitungen), im
Trockenlauf und in Tests ein Fake (tools/signing/fake_storage.py) – nie echtes Netz außerhalb des Workflows.

Konfiguration ausschließlich über Umgebungsvariablen (der Workflow reicht Eingaben nur über env weiter, nie als
Ausdruck in Shell-Code):
  SIGN_BUILD_ID, SIGN_SHA256, SIGN_QUALITY_SHA256,
  SIGN_VERSION, SIGN_KANAL,
  SIGN_VORGAENGER_ID, SIGN_ERSTAUSROLLUNG     Workflow-Eingaben (SIGN_QUALITY_SHA256 bindet quality.json an den lokal
                                             geprüften und freigegebenen Nachweis – kein Ersatz per replace=1)
  SIGNING_STORAGE_TOKEN                      Bearer-Token der Ablage (Repo-Secret, nur in den Ablage-Schritten)
  SIGN_HERAUSGEBER                           erwarteter Zertifikatsinhaber (vars.ARTIFACT_SIGNING_PUBLISHER)
  RUNNER_TEMP, GITHUB_*                      vom Runner gesetzt (GITHUB_EVENT_PATH: repository.full_name wird geprüft)
  SIGN_GH, SIGN_SIGNTOOL, SIGN_TROCKENLAUF,
  SIGN_STORAGE_FAKE                          nur lokal/Trockenlauf; auf jedem GitHub-Runner verboten (GITHUB_ACTIONS=true
                                             oder RUNNER_ENVIRONMENT gesetzt, auch selbst gehostet)
  SIGN_GITHUB_SIMULATION=1                   nur Trockenlauf: GitHub-Prüfungen (Zweig, Annotation) ohne GITHUB_ACTIONS

Unterbefehle in Workflow-Reihenfolge:
  eingaben        Eingaben prüfen, Dateinamen ableiten (nur Build-ID, keine Kundennamen)
  umgebung        Repository (full_name, öffentlich oder privat); Environment release-signing: Pflicht-Reviewer,
                  kein Admin-Bypass, nur Zweig main
  qualitaet       Qualitätsnachweis quality.json aus der Ablage: Manifest-Hash = Download = Eingabe quality_sha256,
                  bestanden=true, Build-ID, remote_e2e_fps
  laden           Manifest (genau ein unsigned, Name, Größe, SHA-256 = Eingabe, noch kein signed) und Download
  vorpruefen      SHA-256, PE/NSIS-Kennung, Hersteller, Build-ID (Versionsressource), unsigniert → Manifest
  nachpruefen     Zertifikatstabelle, Inhalt unverändert, signtool verify /pa /tw /v, Kette, Zeitstempel,
                  Herausgeber, Authenticode-Hash → Nachweise für das Qualitäts-Gate
  hochladen       signierten Installer per PUT <BUILD_ID>/signed mit X-Artifact-SHA256 ablegen (kein Überschreiben)
  ablage-pruefen  Manifest-Hash = geprüfter SHA-256, erneuter Download bitgleich → Bericht ergänzen

Jede Abweichung bricht mit Exit-Code 1 und „FEHLER [code]“ ab. Ein Nachweis mit Status „gueltig“ entsteht nur,
wenn alle Prüfungen bestanden sind und das echte signtool (nicht das Trockenlauf-Fake) geprüft hat.
"""
import datetime as dt
import hashlib
import http.client
import json
import locale
import math
import os
import re
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BERICHT_FORMAT = "insight-artifact-signing/2"
BUILD_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,39}$")          # Cockpit /api/quality: ReleaseIn.version
RELEASE_BUILD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,79}$")  # Cockpit /api/quality: ReleaseIn.build_id
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:|-]{0,79}$")     # Cockpit /api/quality: Release-ID
ARTEFAKT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,119}$")       # Cockpit /api/quality: ArtefaktIn.name
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
KANAELE = ("intern", "pilot", "produktiv")
PRODUKT = "Insight-IT Fernwartung"        # installer.nsi: VIAddVersionKey "ProductName"
HERSTELLER = "Insight-IT GmbH"            # installer.nsi: VIAddVersionKey "CompanyName"
BUILD_ID_SCHLUESSEL = ("FileVersion", "BuildId")    # beide = ${INSTALLER_BUILD_ID} in installer.nsi
AUSSTELLER_PRAEFIX = "Microsoft ID Verified CS "    # Artifact-Signing-Zwischen-CAs (EOC/AOC CA nn)
SIGNATUR_BESCHREIBUNG = "Insight-IT Fernwartung"   # /d der Signatur (UAC-Anzeige), siehe Workflow
REF_ERLAUBT = "refs/heads/main"
MAX_GROESSE = 200 * 1024 * 1024                     # Grenze der Ablage je Datei (API: 413 darüber)
MAX_QUALITY = 1024 * 1024
SIGNTOOL_VERIFY = ("verify", "/pa", "/tw", "/v")
NSIS_KENNUNG = b"\xef\xbe\xad\xdeNullsoftInst"      # firstheader: siginfo 0xDEADBEEF + "NullsoftInst"
FAKE_KENNUNG = "FAKE-SIGNTOOL"                      # Ausgabe von tools/signing/fake_signtool.py
ERLAUBTE_MASCHINEN = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}
WIN_CERT_REVISION, WIN_CERT_PKCS = 0x0200, 0x0002
RT_VERSION = 16
UEBERSCHREIBUNGEN = ("SIGN_GH", "SIGN_SIGNTOOL", "SIGN_TROCKENLAUF", "SIGN_STORAGE_FAKE")
# Schritt-Ausgaben je Unterbefehl (GITHUB_OUTPUT); workflow_check.py prüft Verweise steps.<id>.outputs.<name> dagegen.
AUSGABEN = {"eingaben": ("asset",), "umgebung": (), "qualitaet": ("quality_sha256", "remote_e2e_fps"),
            "laden": ("eingang",), "vorpruefen": ("datei", "manifest", "sha256"),
            "nachpruefen": ("installer", "nachweis_ordner", "sha256_signiert"), "hochladen": (), "ablage-pruefen": ()}
NACHWEIS_DATEIEN = ("release-metadata.json", "signatur-nachweis.json", "signatur-bericht.json")
UMGEBUNG = "release-signing"
ZWEIG = "main"

# ---------------------------------------------------------------- Artefaktablage (Vertrag)
STORAGE_HOST = "cockpit.insight-it.de"
STORAGE_BASIS = "https://%s/api/signing/artifacts" % STORAGE_HOST
STORAGE_HEALTH = "https://%s/api/signing/health" % STORAGE_HOST
TOKEN_ENV = "SIGNING_STORAGE_TOKEN"
TOKEN_RE = re.compile(r"[\x21-\x7e]{16,512}")      # nur mit fullmatch benutzen
KINDS = ("unsigned", "signed", "quality")
QUALITY_DATEI = "quality.json"
FPS_MAX = 1000.0
STATUS_CODES = {400: ("storage_anfrage", "Ablage lehnt die Anfrage ab (ungültige Build-ID oder Datei)"),
                401: ("storage_token", "Ablage lehnt das Token ab (fehlt oder falsch) – Repo-Secret SIGNING_STORAGE_TOKEN prüfen"),
                409: ("storage_konflikt", "Artefakt existiert bereits – kein Überschreiben"),
                413: ("storage_zu_gross", "Datei ist für die Ablage zu groß (max. 200 MiB)"),
                422: ("storage_abgelehnt", "Ablage lehnt den Inhalt ab (Hash, Format oder Qualitätsnachweis ungültig)"),
                503: ("storage_nicht_konfiguriert", "Ablage hat serverseitig kein Token konfiguriert")}


class SigningError(Exception):
    def __init__(self, code, meldung):
        super().__init__("%s: %s" % (code, meldung))
        self.code, self.meldung = code, meldung


# ---------------------------------------------------------------- Namen und Eingaben

def asset_name(build_id):
    """Neutraler Dateiname ohne Kundenbezug – erscheint in Logs, Ablage und Nachweisen."""
    return "insight-fernwartung-%s.exe" % build_id


def ablage_dateiname(build_id, kind):
    """Dateiname laut Ablage-Vertrag: Installer tragen nur die Build-ID, der Qualitätsnachweis heißt quality.json."""
    return QUALITY_DATEI if kind == "quality" else asset_name(build_id)


def auf_github(env=None):
    """Echter GitHub-Runner (gehostet oder selbst gehostet) – unabhängig vom Runner-Typ."""
    env = os.environ if env is None else env
    return env.get("GITHUB_ACTIONS") == "true" or bool(env.get("RUNNER_ENVIRONMENT"))


def github_pruefungen(env=None):
    """GitHub-Prüfungen aktiv: echter Runner oder Trockenlauf mit ausdrücklichem Schalter SIGN_GITHUB_SIMULATION=1."""
    env = os.environ if env is None else env
    return auf_github(env) or env.get("SIGN_GITHUB_SIMULATION") == "1"


def lese_eingaben(env=None):
    env = os.environ if env is None else env
    if auf_github(env):
        gesetzt = [k for k in UEBERSCHREIBUNGEN if env.get(k)]
        if gesetzt:
            raise SigningError("override_verboten", "Werkzeug-Überschreibung auf GitHub-Runnern verboten: " + ", ".join(gesetzt))
    if github_pruefungen(env) and env.get("GITHUB_REF") != REF_ERLAUBT:
        raise SigningError("eingabe_ref", "Signieren nur vom Zweig main (Lauf auf %s)" % (env.get("GITHUB_REF") or "?"))
    build_id = (env.get("SIGN_BUILD_ID") or "").strip()
    if not BUILD_ID_RE.match(build_id):
        raise SigningError("eingabe_build_id", "Build-ID muss JJJJMMTT-HHMMSS sein (build.sh), erhalten %r" % build_id[:40])
    try:
        dt.datetime.strptime(build_id, "%Y%m%d-%H%M%S")
    except ValueError:
        raise SigningError("eingabe_build_id", "Build-ID %s ist kein gültiger Zeitpunkt" % build_id) from None
    sha256 = (env.get("SIGN_SHA256") or "").strip().lower()
    if not SHA256_RE.match(sha256):
        raise SigningError("eingabe_sha256", "SHA-256 muss aus 64 Hex-Zeichen bestehen")
    quality_sha256 = (env.get("SIGN_QUALITY_SHA256") or "").strip().lower()
    if not SHA256_RE.match(quality_sha256):
        raise SigningError("eingabe_quality_sha256", "SHA-256 des Qualitätsnachweises muss aus 64 Hex-Zeichen bestehen")
    version = (env.get("SIGN_VERSION") or "").strip()
    if not VERSION_RE.match(version):
        raise SigningError("eingabe_version", "Version ungültig (erlaubt: Buchstaben, Ziffern, . + -, max. 40)")
    kanal = (env.get("SIGN_KANAL") or "").strip()
    if kanal not in KANAELE:
        raise SigningError("eingabe_kanal", "Kanal muss intern, pilot oder produktiv sein")
    vorgaenger = (env.get("SIGN_VORGAENGER_ID") or "").strip() or None
    if vorgaenger is not None and not RELEASE_ID_RE.match(vorgaenger):
        raise SigningError("eingabe_vorgaenger", "Vorgänger-ID hat kein gültiges Format")
    erst_roh = (env.get("SIGN_ERSTAUSROLLUNG") or "false").strip().lower()
    if erst_roh not in ("true", "false"):
        raise SigningError("eingabe_rollback", "Erstausrollung muss true oder false sein")
    erst = erst_roh == "true"
    if bool(vorgaenger) == erst:
        raise SigningError("eingabe_rollback", "Genau eins angeben: Vorgänger-ID (Rollback-Ziel) oder Erstausrollung")
    return {"build_id": build_id, "sha256": sha256, "quality_sha256": quality_sha256, "version": version, "kanal": kanal,
            "vorgaenger_id": vorgaenger, "erstausrollung": erst, "asset": asset_name(build_id)}


def arbeitsordner(env=None):
    env = os.environ if env is None else env
    temp = env.get("RUNNER_TEMP")
    if not temp or not os.path.isabs(temp):
        raise SigningError("umgebung_fehlt", "RUNNER_TEMP fehlt (Runner-Umgebung)")
    return os.path.join(temp, "insight-signing")


def _pfade(e):
    basis = arbeitsordner()
    return {"basis": basis, "eingang": os.path.join(basis, "eingang"),
            "quelle": os.path.join(basis, "eingang", e["asset"]),
            "unsigniert": os.path.join(basis, "unsigniert", e["asset"]),
            "signiert": os.path.join(basis, "signiert", e["asset"]),
            "manifest": os.path.join(basis, "manifest.json"), "qualitaet": os.path.join(basis, "qualitaet.json"),
            "nachweis": os.path.join(basis, "nachweis")}


# ---------------------------------------------------------------- Repository (öffentlich erlaubt, full_name geprüft)

SICHTBARKEITEN = {False: ("public",), True: ("private", "internal")}


def pruefe_repo(ereignis, repo):
    """Repository aus der Ereignis-Nutzlast (GITHUB_EVENT_PATH) an GITHUB_REPOSITORY binden.

    repository.private darf true oder false sein: Das Repository enthält nur Workflow, Helfer und Doku; Kunden-
    Installer liegen ausschließlich in der privaten Ablage und gelangen nie als Release oder Artefakt nach GitHub.
    In öffentlichen Repositories setzt GitHub Pflicht-Reviewer für Environments auf jedem Plan durch.
    Geprüft wird, dass full_name (owner/repo) gültig ist und genau GITHUB_REPOSITORY entspricht und dass private ein
    Wahrheitswert ist, der zu visibility passt. Sonst Abbruch, bevor ein Token benutzt wird."""
    r = ereignis.get("repository") if isinstance(ereignis, dict) else None
    voll = r.get("full_name") if isinstance(r, dict) else None
    if not isinstance(r, dict) or not isinstance(r.get("private"), bool) or not isinstance(voll, str) \
            or not REPO_RE.match(voll) or not REPO_RE.match(str(repo or "")) or voll.lower() != str(repo).lower():
        raise SigningError("repo_unbekannt", "Repository im Ereignis fehlt, ist ungültig oder ≠ GITHUB_REPOSITORY "
                                             "(repository.full_name/private) – Abbruch vor jedem Ablage-Zugriff")
    sichtbarkeit = r.get("visibility")
    if sichtbarkeit is not None and sichtbarkeit not in SICHTBARKEITEN[r["private"]]:
        raise SigningError("repo_unbekannt", "Sichtbarkeit widersprüchlich (private=%s, visibility=%r)"
                           % (str(r["private"]).lower(), str(sichtbarkeit)[:20]))
    return sichtbarkeit or ("private" if r["private"] else "public")


def lies_ereignis(env=None):
    env = os.environ if env is None else env
    pfad = env.get("GITHUB_EVENT_PATH") or ""
    try:
        if not pfad or os.path.getsize(pfad) > 16 * 1024 * 1024:
            raise OSError
        with open(pfad, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        raise SigningError("repo_unbekannt", "Ereignis-Nutzlast (GITHUB_EVENT_PATH) fehlt oder ist kein JSON – "
                                             "Repository nicht feststellbar") from None


def _repo_pruefen():
    repo = _repo()
    return repo, pruefe_repo(lies_ereignis(), repo)


# ---------------------------------------------------------------- PE-Struktur

def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def pe_layout(data):
    try:
        return _pe_layout(data)
    except struct.error as exc:
        raise SigningError("pe_defekt", "PE-Struktur unvollständig (%s)" % exc) from None


def _pe_layout(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise SigningError("kein_pe", "Keine Windows-Programmdatei (MZ-Kopf fehlt)")
    pe = _u32(data, 0x3C)
    if pe < 0x40 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise SigningError("kein_pe", "PE-Signatur fehlt")
    coff = pe + 4
    maschine, anzahl = _u16(data, coff), _u16(data, coff + 2)
    opt_groesse = _u16(data, coff + 16)
    opt = coff + 20
    if maschine not in ERLAUBTE_MASCHINEN:
        raise SigningError("pe_architektur", "Unerwartete Architektur 0x%04x" % maschine)
    if not 0 < anzahl <= 96 or opt_groesse < 96 or opt + opt_groesse > len(data):
        raise SigningError("pe_defekt", "PE-Kopf unplausibel")
    magic = _u16(data, opt)
    if magic == 0x10B:
        nrva_off, dd = opt + 92, opt + 96
    elif magic == 0x20B:
        nrva_off, dd = opt + 108, opt + 112
    else:
        raise SigningError("pe_defekt", "Unbekannter Optional-Header 0x%04x" % magic)
    if _u32(data, nrva_off) < 5 or dd + 40 > opt + opt_groesse:
        raise SigningError("pe_defekt", "Datenverzeichnis ohne Eintrag für die Zertifikatstabelle")
    sh = opt + opt_groesse
    if sh + 40 * anzahl > len(data):
        raise SigningError("pe_defekt", "Abschnittstabelle abgeschnitten")
    abschnitte = []
    for i in range(anzahl):
        o = sh + 40 * i
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
        abschnitte.append({"name": data[o:o + 8].rstrip(b"\0").decode("latin-1"), "va": va, "vsize": vsize,
                           "rsize": rsize, "rptr": rptr})
    ende = max([_u32(data, opt + 60)] + [a["rptr"] + a["rsize"] for a in abschnitte if a["rsize"]])
    if ende > len(data):
        raise SigningError("pe_defekt", "Abschnitte reichen über das Dateiende")
    return {"maschine": ERLAUBTE_MASCHINEN[maschine], "pruefsumme_off": opt + 64, "secdir_off": dd + 32,
            "sec_va": _u32(data, dd + 32), "sec_size": _u32(data, dd + 36),
            "res_rva": _u32(data, dd + 16), "res_size": _u32(data, dd + 20),
            "abschnitte": abschnitte, "ende_abschnitte": ende}


def _rva_offset(layout, rva, laenge, datenlaenge):
    for a in layout["abschnitte"]:
        rel = rva - a["va"]
        if 0 <= rel and rel + laenge <= a["rsize"] and a["rptr"] + rel + laenge <= datenlaenge:
            return a["rptr"] + rel
    raise ValueError("Ressourcenadresse 0x%x außerhalb der Abschnittsdaten" % rva)


def _a4(x):
    return (x + 3) & ~3


def version_strings(data, layout=None):
    """StringFileInfo-Werte der Versionsressource (ProductName, CompanyName, FileVersion, BuildId …)."""
    layout = layout or pe_layout(data)
    if not layout["res_rva"] or not layout["res_size"]:
        raise SigningError("versionsinfo_fehlt", "Installer ohne Ressourcen – Versionsangaben fehlen")
    try:
        return _version_strings(data, layout)
    except SigningError:
        raise
    except (struct.error, IndexError, UnicodeDecodeError, ValueError) as exc:
        raise SigningError("versionsinfo_defekt", "Versionsressource nicht lesbar (%s)" % exc) from None


def _version_strings(data, layout):
    basis = _rva_offset(layout, layout["res_rva"], 16, len(data))

    def eintraege(off):
        anzahl = _u16(data, off + 12) + _u16(data, off + 14)
        if anzahl > 4096:
            raise ValueError("zu viele Ressourceneinträge")
        return [struct.unpack_from("<II", data, off + 16 + 8 * i) for i in range(anzahl)]

    def unterordner(ziel):
        if not ziel & 0x80000000:
            raise ValueError("Ressourcenbaum unerwartet")
        return basis + (ziel & 0x7FFFFFFF)

    typ = [z for name, z in eintraege(basis) if name == RT_VERSION]
    if not typ:
        raise SigningError("versionsinfo_fehlt", "Keine Versionsressource (RT_VERSION)")
    namen = eintraege(unterordner(typ[0]))
    sprachen = eintraege(unterordner(namen[0][1])) if namen else []
    if not sprachen or sprachen[0][1] & 0x80000000:
        raise ValueError("Versionsressource ohne Daten")
    rva, groesse = struct.unpack_from("<II", data, basis + sprachen[0][1])
    off = _rva_offset(layout, rva, groesse, len(data))
    return _versionsinfo(data[off:off + groesse])


def _block(blob, off, grenze):
    laenge, wert_laenge, typ = struct.unpack_from("<HHH", blob, off)
    ende = off + laenge
    if laenge < 6 or ende > grenze:
        raise ValueError("Versionsblock unplausibel")
    k = off + 6
    while k + 1 < ende and blob[k:k + 2] != b"\0\0":
        k += 2
    return blob[off + 6:k].decode("utf-16-le"), wert_laenge, typ, _a4(k + 2), ende


def _kinder(blob, pos, ende):
    while pos + 6 <= ende and _u16(blob, pos):
        kind = _block(blob, pos, ende)
        yield kind
        pos = _a4(kind[4])


def _versionsinfo(blob):
    schluessel, wert_laenge, _typ, pos, ende = _block(blob, 0, len(blob))
    if schluessel != "VS_VERSION_INFO":
        raise ValueError("VS_VERSION_INFO fehlt")
    werte = {}
    for name, _wl, _t, kpos, kende in _kinder(blob, _a4(pos + wert_laenge), ende):
        if name != "StringFileInfo":
            continue
        for _tabelle, _twl, _tt, spos, tende in _kinder(blob, kpos, kende):
            for sname, _swl, _st, wpos, sende in _kinder(blob, spos, tende):
                roh = blob[wpos:sende]
                roh = roh[:len(roh) - len(roh) % 2]
                werte.setdefault(sname, roh.decode("utf-16-le").split("\0", 1)[0])
    return werte


def nsis_kennung(data, layout):
    """NSIS-firstheader (flags, 0xDEADBEEF, "NullsoftInst", …) im Overlay hinter den PE-Abschnitten."""
    idx = data.find(NSIS_KENNUNG, layout["ende_abschnitte"])
    if idx < 0 or idx - 4 < layout["ende_abschnitte"] or idx + 24 > len(data):
        return False
    gesamt = _u32(data, idx + 20)       # length_of_all_following_data (inkl. firstheader und CRC)
    return 28 <= gesamt and idx - 4 + gesamt <= len(data)


def authenticode_sha256(data, layout=None):
    """Authenticode-PE-Hash: ganze Datei bis zur Zertifikatstabelle ohne Prüfsumme und Zertifikatsverzeichnis."""
    layout = layout or pe_layout(data)
    ende = layout["sec_va"] if layout["sec_size"] else len(data)
    if not layout["ende_abschnitte"] <= ende <= len(data):
        raise SigningError("zertifikatstabelle_lage", "Zertifikatstabelle liegt nicht hinter den Abschnitten")
    p, s = layout["pruefsumme_off"], layout["secdir_off"]
    h = hashlib.sha256()
    h.update(data[:p])
    h.update(data[p + 4:s])
    h.update(data[s + 8:ende])
    return h.hexdigest()


def zertifikatstabelle(data, layout):
    va, groesse = layout["sec_va"], layout["sec_size"]
    if not va and not groesse:
        return []
    if not va or not groesse:
        raise SigningError("signatur_format", "Zertifikatsverzeichnis inkonsistent (Adresse %d, Größe %d)" % (va, groesse))
    if va % 8 or va < layout["ende_abschnitte"] or va + groesse != len(data):
        raise SigningError("zertifikatstabelle_lage", "Zertifikatstabelle nicht 8-Byte-ausgerichtet am Dateiende")
    eintraege, pos = [], va
    while pos + 8 <= va + groesse:
        laenge, revision, typ = struct.unpack_from("<IHH", data, pos)
        if laenge < 8 or pos + laenge > va + groesse:
            raise SigningError("signatur_format", "WIN_CERTIFICATE-Länge unplausibel")
        eintraege.append({"offset": pos, "laenge": laenge, "revision": revision, "typ": typ})
        pos += (laenge + 7) & ~7
    return eintraege


def inhalt_vergleich(unsigniert, signiert, lay_u, lay_s):
    """Signierte Datei = unsignierte Datei + ≤ 7 Nullbytes + Zertifikatstabelle; sonst nur Prüfsumme/Verzeichnis neu."""
    n, c = len(unsigniert), lay_s["sec_va"]
    if not n <= c < n + 8:
        raise SigningError("inhalt_geaendert", "Signierte Datei ist nicht „geprüfte Datei + Signatur“ (Längen %d/%d)" % (n, c))
    if any(signiert[n:c]):
        raise SigningError("inhalt_geaendert", "Auffüllbytes vor der Signatur sind nicht null")
    if (lay_u["pruefsumme_off"], lay_u["secdir_off"]) != (lay_s["pruefsumme_off"], lay_s["secdir_off"]):
        raise SigningError("inhalt_geaendert", "PE-Kopf der signierten Datei weicht ab")

    def normiert(daten, lay):
        b = bytearray(daten[:n])
        b[lay["pruefsumme_off"]:lay["pruefsumme_off"] + 4] = b"\0" * 4
        b[lay["secdir_off"]:lay["secdir_off"] + 8] = b"\0" * 8
        return bytes(b)

    if normiert(signiert, lay_s) != normiert(unsigniert, lay_u):
        raise SigningError("inhalt_geaendert", "Inhalt außerhalb von Prüfsumme und Signaturverzeichnis verändert")
    return c - n


def pruefe_installer(data, build_id):
    """Kennzeichen des Fernwartungs-Installers; liefert (Layout, Versionswerte)."""
    layout = pe_layout(data)
    if not nsis_kennung(data, layout):
        raise SigningError("kein_nsis", "Keine NSIS-Installerdaten (firstheader fehlt)")
    werte = version_strings(data, layout)
    for schluessel, soll in (("ProductName", PRODUKT), ("CompanyName", HERSTELLER)):
        if werte.get(schluessel) != soll:
            raise SigningError("hersteller_abweichung", "%s = %r, erwartet %r" % (schluessel, werte.get(schluessel), soll))
    for schluessel in BUILD_ID_SCHLUESSEL:
        if werte.get(schluessel) != build_id:
            raise SigningError("build_id_abweichung", "%s im Installer = %r, erwartet %s" % (schluessel, werte.get(schluessel), build_id))
    return layout, werte


# ---------------------------------------------------------------- signtool-Ausgabe

def parse_signtool(text):
    erg = {"signaturen": 0, "hash": None, "kette": [], "zeitstempel": None, "zeitstempel_kette": [],
           "erfolgreich": False, "anzahl_verifiziert": None, "warnungen": None, "fehler": None, "fake": False}
    bereich, aktuell = None, None
    for zeile in text.splitlines():
        s = zeile.strip()
        if not s:
            continue
        if FAKE_KENNUNG in s:
            erg["fake"] = True
        einrueckung = len(zeile) - len(zeile.lstrip(" "))
        m = re.match(r"Hash of file \(sha256\):\s*([0-9A-Fa-f]{64})$", s)
        if m:
            erg["hash"] = m.group(1).lower()
            continue
        if s.startswith("Signature Index:"):
            erg["signaturen"] += 1
        elif s.startswith("Signing Certificate Chain:"):
            bereich, aktuell = "kette", None
        elif s.startswith("The signature is timestamped:"):
            erg["zeitstempel"], bereich, aktuell = s.split(":", 1)[1].strip(), None, None
        elif s.startswith("Timestamp Verified by:"):
            bereich, aktuell = "zeitstempel_kette", None
        elif s.startswith("Issued to:") and bereich:
            aktuell = {"ausgestellt_fuer": s.split(":", 1)[1].strip(), "ausgestellt_von": "", "ebene": einrueckung}
            erg[bereich].append(aktuell)
        elif aktuell is not None and s.startswith(("Issued by:", "Expires:", "SHA1 hash:")):
            feld = {"Issued by": "ausgestellt_von", "Expires": "ablauf", "SHA1 hash": "sha1"}[s.split(":", 1)[0]]
            aktuell[feld] = s.split(":", 1)[1].strip()
        elif s.startswith("Successfully verified:"):
            erg["erfolgreich"], bereich, aktuell = True, None, None
        else:
            for muster, feld in ((r"Number of files successfully Verified:\s*(\d+)$", "anzahl_verifiziert"),
                                 (r"Number of warnings:\s*(\d+)$", "warnungen"), (r"Number of errors:\s*(\d+)$", "fehler")):
                m = re.match(muster, s)
                if m:
                    erg[feld] = int(m.group(1))
            if s.startswith(("File is not timestamped", "SignTool Error", "SignTool Warning")):
                bereich, aktuell = None, None
    return erg


def bewerte_signtool(erg, exitcode, herausgeber, authenticode):
    """Strenge Auswertung von `signtool verify /pa /tw /v`; liefert das Blattzertifikat oder wirft SigningError."""
    if exitcode != 0:
        raise SigningError("signtool_verify", "signtool verify meldet Exit %d (ungültig, nicht vertrauenswürdig oder "
                                              "Warnung, z. B. fehlender Zeitstempel)" % exitcode)
    if not erg["erfolgreich"] or erg["fehler"] != 0 or erg["warnungen"] != 0 or erg["anzahl_verifiziert"] != 1:
        raise SigningError("nicht_verifiziert", "signtool meldet keine fehlerfreie Prüfung (verifiziert %s, Warnungen %s, "
                                                "Fehler %s)" % (erg["anzahl_verifiziert"], erg["warnungen"], erg["fehler"]))
    if erg["signaturen"] != 1:
        raise SigningError("signatur_format", "Genau eine Signatur erwartet, gefunden %d" % erg["signaturen"])
    if not erg["kette"]:
        raise SigningError("signtool_ausgabe", "Zertifikatskette fehlt in der signtool-Ausgabe")
    blatt = max(reversed(erg["kette"]), key=lambda z: z["ebene"])
    if len(erg["kette"]) < 2 or blatt["ausgestellt_fuer"] == blatt["ausgestellt_von"]:
        raise SigningError("selbstsigniert", "Selbstsigniertes Zertifikat bzw. Kette ohne ausstellende CA – nie ein Erfolg")
    if not blatt["ausgestellt_von"].startswith(AUSSTELLER_PRAEFIX):
        raise SigningError("aussteller_abweichung", "Aussteller %r ist keine Artifact-Signing-CA (%s…)"
                           % (blatt["ausgestellt_von"], AUSSTELLER_PRAEFIX.strip()))
    if blatt["ausgestellt_fuer"] != herausgeber:
        raise SigningError("herausgeber_abweichung", "Zertifikatsinhaber %r, erwartet %r"
                           % (blatt["ausgestellt_fuer"], herausgeber))
    if not erg["zeitstempel"] or not erg["zeitstempel_kette"]:
        raise SigningError("zeitstempel_fehlt", "Signatur ohne geprüften RFC-3161-Zeitstempel")
    if erg["hash"] != authenticode:
        raise SigningError("authenticode_abweichung", "signtool prüfte einen anderen Inhalt (Authenticode-Hash abweichend)")
    return blatt


def finde_signtool(env=None):
    env = os.environ if env is None else env
    if env.get("SIGN_SIGNTOOL"):
        return env["SIGN_SIGNTOOL"]
    if os.name != "nt":
        raise SigningError("signtool_fehlt", "signtool gibt es nur unter Windows (Trockenlauf: SIGN_SIGNTOOL)")
    basis = os.path.join(env.get("ProgramFiles(x86)") or r"C:\Program Files (x86)", "Windows Kits", "10", "bin")
    kandidaten = []
    for name in os.listdir(basis) if os.path.isdir(basis) else ():
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", name)
        pfad = os.path.join(basis, name, "x64", "signtool.exe")
        if m and os.path.isfile(pfad):
            kandidaten.append((tuple(int(x) for x in m.groups()), pfad))
    if not kandidaten:
        raise SigningError("signtool_fehlt", "signtool.exe nicht im Windows SDK gefunden")
    return max(kandidaten)[1]


def _werkzeug_argv(pfad, *args):
    # .py nur im Trockenlauf (Fake-Werkzeuge); auf jedem GitHub-Runner verbietet lese_eingaben jede Überschreibung.
    return [sys.executable, pfad, *args] if pfad.lower().endswith(".py") else [pfad, *args]


def _dekodiere(roh):
    try:
        return roh.decode("utf-8")
    except UnicodeDecodeError:
        return roh.decode(locale.getpreferredencoding(False) or "cp1252", "replace")


# ---------------------------------------------------------------- Nachweise (Form wie Cockpit /api/quality)

def pruefe_release_body(b):
    soll = ("version", "git_sha", "build_id", "kanal", "artefakte", "vorgaenger_id", "erstausrollung", "symbole", "notiz")
    ok = (list(b) == list(soll) and VERSION_RE.match(b["version"]) and GIT_SHA_RE.match(b["git_sha"])
          and RELEASE_BUILD_RE.match(b["build_id"]) and b["kanal"] in KANAELE and len(b["artefakte"]) == 1
          and (b["vorgaenger_id"] is None or (isinstance(b["vorgaenger_id"], str) and RELEASE_ID_RE.match(b["vorgaenger_id"])))
          and isinstance(b["erstausrollung"], bool) and b["symbole"] == [] and len(b["notiz"]) <= 2000)
    a = b["artefakte"][0] if b.get("artefakte") else {}
    ok = ok and list(a) == ["name", "sha256", "groesse"] and ARTEFAKT_RE.match(a["name"]) \
        and SHA256_RE.match(a["sha256"]) and isinstance(a["groesse"], int) and a["groesse"] >= 0
    if not ok:
        raise SigningError("nachweis_ungueltig", "Release-Metadaten entsprechen nicht dem Schema des Qualitäts-Gates")
    return b


def pruefe_nachweis_body(b):
    ok = (list(b) == ["artefakt", "sha256", "status", "aussteller", "zeitstempel", "werkzeug", "lauf_url"]
          and 0 < len(b["artefakt"]) <= 120 and SHA256_RE.match(b["sha256"]) and b["status"] in ("gueltig", "ungueltig")
          and len(b["aussteller"]) <= 200 and isinstance(b["zeitstempel"], bool) and len(b["werkzeug"]) <= 200
          and len(b["lauf_url"]) <= 300 and re.fullmatch(r"(https://\S+)?", b["lauf_url"]))
    if not ok:
        raise SigningError("nachweis_ungueltig", "Signaturnachweis entspricht nicht dem Schema des Qualitäts-Gates")
    return b


def _lauf_url(env):
    server, repo = env.get("GITHUB_SERVER_URL", ""), env.get("GITHUB_REPOSITORY", "")
    lauf, versuch = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    if server.startswith("https://") and REPO_RE.match(repo) and lauf.isdigit() and versuch.isdigit():
        return "%s/%s/actions/runs/%s/attempts/%s" % (server.rstrip("/"), repo, lauf, versuch)
    return ""


# ---------------------------------------------------------------- Artefaktablage: Transport und Client

class _KeineWeiterleitung(urllib.request.HTTPRedirectHandler):
    """Weiterleitungen nie folgen: urllib würde den Authorization-Kopf an das neue Ziel mitschicken."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SigningError("storage_weiterleitung", "Ablage antwortet mit Weiterleitung (HTTP %d) – abgelehnt" % code)


def pruefe_storage_url(url):
    """Nur https://cockpit.insight-it.de[:443]/api/signing/… ohne Zugangsdaten in der URL."""
    try:
        t = urllib.parse.urlsplit(url)
        port = t.port
    except ValueError:
        raise SigningError("storage_url", "Ablage-URL ungültig") from None
    if t.scheme != "https" or t.hostname != STORAGE_HOST or port not in (None, 443) or t.username or t.password \
            or not t.path.startswith("/api/signing/") or t.fragment:
        raise SigningError("storage_url", "Ablage-URL nicht erlaubt (nur https://%s/api/signing/…)" % STORAGE_HOST)
    return url


def _lies_begrenzt(antwort, max_bytes):
    daten = antwort.read(max_bytes + 1)
    if len(daten) > max_bytes:
        raise SigningError("storage_zu_gross", "Antwort der Ablage größer als %d Bytes – abgebrochen" % max_bytes)
    return daten


class HttpsTransport:
    """Produktiver Transport (urllib, Standardbibliothek): TLS mit Systemzertifikaten, keine Weiterleitungen, Zeitlimit.

    Aufruf transport(methode, url, kopf, body, max_antwort) → (status, bytes). Meldungen enthalten nie Token oder
    Antworttexte der Ablage."""

    def __init__(self, timeout=600):
        self.timeout = timeout
        kontext = ssl.create_default_context()
        kontext.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(_KeineWeiterleitung(), urllib.request.HTTPSHandler(context=kontext))

    def __call__(self, methode, url, kopf, body, max_antwort):
        pruefe_storage_url(url)
        anfrage = urllib.request.Request(url, data=body, method=methode, headers=dict(kopf))
        try:
            with self.opener.open(anfrage, timeout=self.timeout) as antwort:
                return antwort.status, _lies_begrenzt(antwort, max_antwort)
        except urllib.error.HTTPError as exc:
            exc.close()
            return exc.code, b""
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as exc:
            raise SigningError("storage_nicht_erreichbar", "Ablage nicht erreichbar (%s)" % exc.__class__.__name__) from None


def storage_transport(env=None):
    """Produktiv HttpsTransport; SIGN_STORAGE_FAKE=<ordner> nur lokal/Trockenlauf (auf GitHub-Runnern verboten)."""
    env = os.environ if env is None else env
    ordner = env.get("SIGN_STORAGE_FAKE")
    if ordner:
        if auf_github(env):
            raise SigningError("override_verboten", "SIGN_STORAGE_FAKE auf GitHub-Runnern verboten")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import fake_storage
        return fake_storage.DateiTransport(ordner)
    return HttpsTransport()


def lies_token(env=None):
    env = os.environ if env is None else env
    token = env.get(TOKEN_ENV) or ""
    if not token.strip():
        raise SigningError("storage_token_fehlt", "Repo-Secret SIGNING_STORAGE_TOKEN fehlt oder ist leer")
    if not TOKEN_RE.fullmatch(token):
        raise SigningError("storage_token_format", "SIGNING_STORAGE_TOKEN hat kein gültiges Format (16–512 sichtbare "
                                                   "ASCII-Zeichen, keine Leerzeichen/Zeilenumbrüche)")
    return token


class Ablage:
    """Client der privaten Signatur-Artefaktablage nach Vertrag (nur die vom Signaturpfad gebrauchten Endpunkte)."""

    def __init__(self, transport, token, basis=STORAGE_BASIS):
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            raise SigningError("storage_token_format", "Token der Ablage ungültig")
        self.transport, self._token, self.basis = transport, token, pruefe_storage_url(basis.rstrip("/"))

    def __repr__(self):                       # nie das Token ausgeben
        return "Ablage(%s)" % self.basis

    def _url(self, build_id, teil):
        if not isinstance(build_id, str) or not BUILD_ID_RE.fullmatch(build_id) or teil not in KINDS + ("manifest",):
            raise SigningError("storage_anfrage", "Ungültige Build-ID oder Artefaktart")
        return "%s/%s/%s" % (self.basis, build_id, teil)

    def _anfrage(self, methode, url, body=None, kopf=None, max_antwort=64 * 1024, fehlt=("storage_fehlt", "fehlt")):
        k = {"Authorization": "Bearer " + self._token, "Accept": "*/*", "User-Agent": "insight-signing/2"}
        k.update(kopf or {})
        status, daten = self.transport(methode, url, k, body, max_antwort)
        if status in (200, 201):
            return daten
        if status == 404:
            raise SigningError(fehlt[0], "Ablage meldet 404: %s" % fehlt[1])
        code, meldung = STATUS_CODES.get(status, ("storage_fehler", "Ablage antwortet mit HTTP %s" % status))
        raise SigningError(code, "%s (HTTP %s)" % (meldung, status))

    def manifest(self, build_id):
        roh = self._anfrage("GET", self._url(build_id, "manifest"), kopf={"Accept": "application/json"},
                            fehlt=("storage_fehlt", "Build %s ist nicht (mehr) in der Ablage" % build_id))
        try:
            return json.loads(roh.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise SigningError("manifest_ungueltig", "Manifest der Ablage ist kein JSON") from None

    def lade(self, build_id, kind, max_bytes, fehlt_code="storage_fehlt"):
        return self._anfrage("GET", self._url(build_id, kind), max_antwort=max_bytes,
                             fehlt=(fehlt_code, "%s von %s fehlt" % (kind, build_id)))

    def lege_ab(self, build_id, kind, data, sha256):
        if hashlib.sha256(data).hexdigest() != sha256:
            raise SigningError("datei_veraendert", "Hochzuladende Datei ≠ geprüfter SHA-256")
        typ = "application/json" if kind == "quality" else "application/octet-stream"
        self._anfrage("PUT", self._url(build_id, kind), body=data,
                      kopf={"X-Artifact-SHA256": sha256, "Content-Type": typ, "Content-Length": str(len(data))})


def pruefe_manifest(m, build_id, kind, sha256=None, fehlt_code="asset_fehlt", abweichung_code="digest_abweichung"):
    """Manifest {build_id, artifacts:[{kind, filename, sha256, size, uploaded_at}]}: genau ein Eintrag dieser Art,
    Dateiname laut Vertrag, Größe plausibel, Hash (falls erwartet) gleich. Liefert den Eintrag."""
    if not isinstance(m, dict) or m.get("build_id") != build_id or not isinstance(m.get("artifacts"), list) \
            or not all(isinstance(a, dict) for a in m["artifacts"]):
        raise SigningError("manifest_ungueltig", "Manifest gehört nicht zu Build %s oder ist unvollständig" % build_id)
    treffer = [a for a in m["artifacts"] if a.get("kind") == kind]
    if not treffer:
        raise SigningError(fehlt_code, "Ablage enthält kein %s für Build %s" % (kind, build_id))
    if len(treffer) > 1:
        raise SigningError("asset_mehrdeutig", "%s ist mehrfach im Manifest" % kind)
    a = treffer[0]
    grenze = MAX_QUALITY if kind == "quality" else MAX_GROESSE
    if a.get("filename") != ablage_dateiname(build_id, kind):
        raise SigningError("asset_name", "Dateiname %r ≠ %s" % (str(a.get("filename"))[:80], ablage_dateiname(build_id, kind)))
    if isinstance(a.get("size"), bool) or not isinstance(a.get("size"), int) or not 0 < a["size"] <= grenze:
        raise SigningError("asset_groesse", "Größe von %s unplausibel (%r)" % (kind, a.get("size")))
    if not isinstance(a.get("sha256"), str) or not SHA256_RE.fullmatch(a["sha256"]):
        raise SigningError("manifest_ungueltig", "SHA-256 von %s fehlt im Manifest" % kind)
    if sha256 is not None and a["sha256"] != sha256:
        raise SigningError(abweichung_code, "SHA-256 von %s in der Ablage ≠ erwartet" % kind)
    return a


def _zeitpunkt(wert):
    return wert if isinstance(wert, str) and re.fullmatch(r"[0-9T:.+Z-]{10,40}", wert) else None


def pruefe_quality(q, build_id):
    """Qualitätsnachweis quality.json: bestanden=true, gleiche Build-ID, remote_e2e_fps als endliche Zahl > 0."""
    if not isinstance(q, dict):
        raise SigningError("quality_ungueltig", "quality.json ist kein JSON-Objekt")
    if q.get("bestanden") is not True:
        raise SigningError("quality_ungueltig", "Qualitätsnachweis nicht bestanden (bestanden ≠ true)")
    if q.get("build_id") != build_id:
        raise SigningError("quality_ungueltig", "Qualitätsnachweis gehört zu Build %r, erwartet %s"
                           % (str(q.get("build_id"))[:40], build_id))
    fps = q.get("remote_e2e_fps")
    if isinstance(fps, bool) or not isinstance(fps, (int, float)) or not math.isfinite(fps) or not 0 < fps <= FPS_MAX:
        raise SigningError("quality_ungueltig", "remote_e2e_fps fehlt oder ist keine plausible Zahl")
    return {"build_id": build_id, "bestanden": True, "remote_e2e_fps": float(fps)}


def _ablage(env=None):
    return Ablage(storage_transport(env), lies_token(env))


def _schreibe_atomar(pfad, data):
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".laden-", dir=os.path.dirname(pfad))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, pfad)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------- GitHub-Ausgaben

def _ausgabe(name, wert):
    if "\n" in wert or "\r" in wert:
        raise SigningError("umgebung_fehlt", "Ausgabewert %s enthält einen Zeilenumbruch" % name)
    pfad = os.environ.get("GITHUB_OUTPUT")
    if pfad:
        with open(pfad, "a", encoding="utf-8") as fh:
            fh.write("%s=%s\n" % (name, wert))


def _zusammenfassung(titel, zeilen):
    text = "### %s\n\n| Prüfung | Ergebnis |\n|---|---|\n" % titel
    text += "".join("| %s | %s |\n" % (k, str(v).replace("|", "/")) for k, v in zeilen) + "\n"
    print(text, end="")
    pfad = os.environ.get("GITHUB_STEP_SUMMARY")
    if pfad:
        with open(pfad, "a", encoding="utf-8") as fh:
            fh.write(text)


def _lies(pfad, code="datei_fehlt"):
    if not os.path.isfile(pfad):
        raise SigningError(code, "Datei fehlt: %s" % os.path.basename(pfad))
    if os.path.getsize(pfad) > MAX_GROESSE:
        raise SigningError("datei_zu_gross", "%s ist größer als %d MiB" % (os.path.basename(pfad), MAX_GROESSE >> 20))
    with open(pfad, "rb") as fh:
        return fh.read()


def _schreibe_json(pfad, obj):
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    with open(pfad, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False, indent=1) + "\n")


def _jetzt():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _gh(args, timeout):
    werkzeug = os.environ.get("SIGN_GH") or "gh"
    try:
        return subprocess.run(_werkzeug_argv(werkzeug, *args), capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SigningError("gh_fehlt", "gh nicht ausführbar (%s)" % exc.__class__.__name__) from None


def _erste_zeile(roh):
    text = _dekodiere(roh or b"").strip()
    return text.splitlines()[0][:200] if text else "keine Meldung"


# ---------------------------------------------------------------- Unterbefehle

def cmd_eingaben():
    e = lese_eingaben()
    _ausgabe("asset", e["asset"])
    _zusammenfassung("Eingaben geprüft", [
        ("Build-ID", e["build_id"]), ("Erwarteter SHA-256 (unsigniert)", e["sha256"]),
        ("Erwarteter SHA-256 (quality.json)", e["quality_sha256"]),
        ("Ablage", "%s/{unsigned,quality,signed}" % e["build_id"]), ("Installer", e["asset"]),
        ("Version / Kanal", "%s / %s" % (e["version"], e["kanal"])),
        ("Rollback", "Erstausrollung" if e["erstausrollung"] else "Vorgänger " + e["vorgaenger_id"])])


def _repo():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not REPO_RE.match(repo):
        raise SigningError("umgebung_fehlt", "GITHUB_REPOSITORY fehlt oder ist ungültig")
    return repo


def _gh_json(pfad, code, was):
    r = _gh(["api", pfad], 120)
    if r.returncode != 0:
        raise SigningError(code, "%s nicht lesbar: %s" % (was, _erste_zeile(r.stderr)))
    try:
        return json.loads(_dekodiere(r.stdout))
    except ValueError:
        raise SigningError(code, "Antwort zu %s ist kein JSON" % was) from None


def pruefe_umgebung(umgebung, zweige):
    """Environment-Schutz als Vorbedingung: Pflicht-Reviewer und Bereitstellung nur vom Zweig main.

    In öffentlichen Repositories gibt es Pflicht-Reviewer auf jedem GitHub-Plan; fehlt die Regel trotzdem (nicht
    eingetragen, oder privates Repository ohne Enterprise), bricht der Lauf ab, statt ohne Freigabe zu signieren."""
    if not isinstance(umgebung, dict) or umgebung.get("name") != UMGEBUNG:
        raise SigningError("umgebung_fehlt", "Environment %s existiert nicht" % UMGEBUNG)
    regeln = umgebung.get("protection_rules") or []
    reviewer = [r for r in regeln if isinstance(r, dict) and r.get("type") == "required_reviewers" and r.get("reviewers")]
    if not reviewer:
        raise SigningError("umgebung_ungeschuetzt", "Environment %s ohne Pflicht-Reviewer – keine manuelle Freigabe "
                                                    "(im Portal eintragen; privates Repository: nur mit GitHub Enterprise)" % UMGEBUNG)
    if umgebung.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        raise SigningError("umgebung_zweige", "Environment %s muss auf ausgewählte Zweige beschränkt sein" % UMGEBUNG)
    regeln_zweige = (zweige or {}).get("branch_policies") if isinstance(zweige, dict) else None
    if not isinstance(regeln_zweige, list) or [(z.get("name"), z.get("type", "branch")) for z in regeln_zweige
                                               if isinstance(z, dict)] != [(ZWEIG, "branch")]:
        raise SigningError("umgebung_zweige", "Environment %s darf nur vom Zweig %s bereitgestellt werden" % (UMGEBUNG, ZWEIG))
    hinweise = []
    if "can_admins_bypass" in umgebung:
        if umgebung["can_admins_bypass"] is not False:
            raise SigningError("umgebung_admin_bypass", "Environment %s erlaubt Administratoren, die Schutzregeln zu umgehen "
                                                        "(can_admins_bypass) – im Portal abwählen" % UMGEBUNG)
    else:
        hinweise.append("can_admins_bypass nicht gemeldet – im Portal prüfen: „Allow administrators to bypass configured "
                        "protection rules“ muss aus sein")
    if not any(r.get("prevent_self_review") for r in reviewer):
        hinweise.append("Prevent self-review ist aus – mit zweiter Person aktivieren (Vier-Augen)")
    return sum(len(r["reviewers"]) for r in reviewer), hinweise


def cmd_umgebung():
    lese_eingaben()
    repo, sichtbarkeit = _repo_pruefen()
    umgebung = _gh_json("repos/%s/environments/%s" % (repo, UMGEBUNG), "umgebung_fehlt", "Environment " + UMGEBUNG)
    zweige = _gh_json("repos/%s/environments/%s/deployment-branch-policies" % (repo, UMGEBUNG), "umgebung_zweige",
                      "Zweigregeln von " + UMGEBUNG)
    anzahl, hinweise = pruefe_umgebung(umgebung, zweige)
    _zusammenfassung("Environment-Schutz geprüft", [
        ("Repository", "%s (%s; Installer nur in der privaten Ablage)" % (repo, sichtbarkeit)), ("Environment", UMGEBUNG),
        ("Pflicht-Reviewer", "%d eingetragen" % anzahl), ("Bereitstellung", "nur Zweig " + ZWEIG)]
        + [("Hinweis", h) for h in hinweise])


def cmd_qualitaet():
    e = lese_eingaben()
    p = _pfade(e)
    _repo_pruefen()
    ablage = _ablage()
    eintrag = pruefe_manifest(ablage.manifest(e["build_id"]), e["build_id"], "quality", e["quality_sha256"],
                              fehlt_code="quality_fehlt", abweichung_code="quality_abweichung")
    roh = ablage.lade(e["build_id"], "quality", MAX_QUALITY, fehlt_code="quality_fehlt")
    sha = hashlib.sha256(roh).hexdigest()
    if sha != eintrag["sha256"] or len(roh) != eintrag["size"]:
        raise SigningError("quality_abweichung", "Geladener Qualitätsnachweis ≠ Manifest (SHA-256/Größe)")
    if sha != e["quality_sha256"]:      # doppelt: Manifest-Hash wurde schon gegen die Eingabe geprüft
        raise SigningError("quality_abweichung", "Qualitätsnachweis ≠ freigegebener Nachweis (Eingabe quality_sha256)")
    try:
        obj = json.loads(roh.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SigningError("quality_ungueltig", "quality.json ist kein JSON") from None
    q = pruefe_quality(obj, e["build_id"])
    q["sha256"] = sha
    _schreibe_json(p["qualitaet"], q)
    _ausgabe("quality_sha256", sha)
    _ausgabe("remote_e2e_fps", "%g" % q["remote_e2e_fps"])
    _zusammenfassung("Qualitätsnachweis geprüft", [
        ("Build-ID", e["build_id"]), ("bestanden", "true"), ("remote_e2e_fps", "%g" % q["remote_e2e_fps"]),
        ("SHA-256 quality.json", "%s (= Eingabe quality_sha256)" % sha)])


def cmd_laden():
    e = lese_eingaben()
    p = _pfade(e)
    _repo_pruefen()
    ablage = _ablage()
    m = ablage.manifest(e["build_id"])
    eintrag = pruefe_manifest(m, e["build_id"], "unsigned", e["sha256"])
    if any(isinstance(a, dict) and a.get("kind") == "signed" for a in m["artifacts"]):
        raise SigningError("signiert_vorhanden", "Für Build %s liegt bereits ein signierter Installer in der Ablage – kein "
                                                 "zweiter Signaturlauf (Build neu hochladen)" % e["build_id"])
    data = ablage.lade(e["build_id"], "unsigned", MAX_GROESSE, fehlt_code="asset_fehlt")
    if len(data) != eintrag["size"] or hashlib.sha256(data).hexdigest() != e["sha256"]:
        raise SigningError("download_abweichung", "Download ≠ Manifest/erwarteter SHA-256 (%d Bytes, Manifest %d)"
                           % (len(data), eintrag["size"]))
    if os.path.exists(p["quelle"]):
        os.remove(p["quelle"])
    _schreibe_atomar(p["quelle"], data)
    _ausgabe("eingang", p["eingang"])
    _zusammenfassung("Unsignierten Installer aus der Ablage geladen", [
        ("Ablage", "%s/unsigned" % e["build_id"]), ("Datei", e["asset"]), ("Größe", "%d Bytes" % len(data)),
        ("SHA-256", "= Eingabe und Manifest"), ("hochgeladen am", _zeitpunkt(eintrag.get("uploaded_at")) or "?")])


def cmd_vorpruefen():
    e = lese_eingaben()
    p = _pfade(e)
    data = _lies(p["quelle"])
    sha = hashlib.sha256(data).hexdigest()
    if sha != e["sha256"]:
        raise SigningError("sha256_abweichung", "SHA-256 des Installers %s… ≠ erwartet %s…" % (sha[:16], e["sha256"][:16]))
    layout, werte = pruefe_installer(data, e["build_id"])
    if layout["sec_va"] or layout["sec_size"]:
        raise SigningError("bereits_signiert", "Installer enthält schon eine Signatur – nur frische, unsignierte Builds")
    authenticode = authenticode_sha256(data, layout)
    for ziel in (p["unsigniert"], p["signiert"]):
        os.makedirs(os.path.dirname(ziel), exist_ok=True)
        shutil.copyfile(p["quelle"], ziel)
        if hashlib.sha256(_lies(ziel)).hexdigest() != sha:
            raise SigningError("datei_veraendert", "Arbeitskopie %s weicht ab" % os.path.basename(os.path.dirname(ziel)))
    manifest = {"format": BERICHT_FORMAT, "asset": e["asset"], "ablage": "%s/unsigned" % e["build_id"],
                "build_id": e["build_id"], "sha256_unsigniert": sha, "groesse_unsigniert": len(data),
                "authenticode_sha256_unsigniert": authenticode, "maschine": layout["maschine"], "nsis": True,
                "versionsangaben": {k: werte[k] for k in ("ProductName", "CompanyName", "FileVersion", "BuildId")},
                "geprueft_am": _jetzt()}
    _schreibe_json(p["manifest"], manifest)
    _ausgabe("datei", p["signiert"])
    _ausgabe("manifest", p["manifest"])
    _ausgabe("sha256", sha)
    _zusammenfassung("Vorprüfung bestanden", [
        ("Datei", e["asset"]), ("SHA-256 (unsigniert)", sha), ("Größe", "%d Bytes" % len(data)),
        ("Build-ID (FileVersion/BuildId)", e["build_id"]), ("Produkt / Hersteller", "%s / %s" % (PRODUKT, HERSTELLER)),
        ("NSIS-Kennung", "vorhanden"), ("Architektur", layout["maschine"]), ("Signatur vorher", "keine"),
        ("Authenticode-Hash", authenticode)])


def _lies_qualitaet(p, build_id, quality_sha256):
    try:
        with open(p["qualitaet"], encoding="utf-8") as fh:
            q = json.load(fh)
    except (OSError, ValueError):
        raise SigningError("quality_fehlt", "Geprüfter Qualitätsnachweis fehlt – Schritt qualitaet nicht gelaufen") from None
    geprueft = pruefe_quality(q, build_id)
    if not isinstance(q.get("sha256"), str) or not SHA256_RE.match(q["sha256"]):
        raise SigningError("quality_fehlt", "Geprüfter Qualitätsnachweis ohne SHA-256")
    if q["sha256"] != quality_sha256:
        raise SigningError("quality_abweichung", "Geprüfter Qualitätsnachweis ≠ Eingabe quality_sha256")
    geprueft["sha256"] = q["sha256"]
    return geprueft


def cmd_nachpruefen():
    e = lese_eingaben()
    p = _pfade(e)
    herausgeber = (os.environ.get("SIGN_HERAUSGEBER") or "").strip()
    if not herausgeber:
        raise SigningError("herausgeber_fehlt", "Variable ARTIFACT_SIGNING_PUBLISHER (erwarteter Zertifikatsinhaber) fehlt")
    if not os.path.isfile(p["manifest"]):
        raise SigningError("manifest_fehlt", "Manifest der Vorprüfung fehlt")
    with open(p["manifest"], encoding="utf-8") as fh:
        manifest = json.load(fh)
    if (manifest.get("asset"), manifest.get("build_id"), manifest.get("sha256_unsigniert")) != (e["asset"], e["build_id"], e["sha256"]):
        raise SigningError("manifest_abweichung", "Manifest passt nicht zu den Eingaben")
    qualitaet = _lies_qualitaet(p, e["build_id"], e["quality_sha256"])
    unsigniert, signiert = _lies(p["unsigniert"]), _lies(p["signiert"], "signatur_fehlt")
    if hashlib.sha256(unsigniert).hexdigest() != e["sha256"]:
        raise SigningError("referenz_abweichung", "Referenzkopie des unsignierten Installers verändert")
    sha_s = hashlib.sha256(signiert).hexdigest()
    if sha_s == e["sha256"]:
        raise SigningError("signatur_fehlt", "Installer nach dem Signierschritt unverändert – keine Signatur")
    lay_s = pe_layout(signiert)
    tabelle = zertifikatstabelle(signiert, lay_s)
    if not tabelle:
        raise SigningError("signatur_fehlt", "Keine Zertifikatstabelle im Installer")
    if len(tabelle) != 1 or (tabelle[0]["revision"], tabelle[0]["typ"]) != (WIN_CERT_REVISION, WIN_CERT_PKCS):
        raise SigningError("signatur_format", "Genau ein WIN_CERTIFICATE (Revision 2.0, PKCS#7) erwartet")
    auffuellung = inhalt_vergleich(unsigniert, signiert, pe_layout(unsigniert), lay_s)
    pruefe_installer(signiert, e["build_id"])
    authenticode = authenticode_sha256(signiert, lay_s)
    werkzeug = finde_signtool()
    try:
        r = subprocess.run(_werkzeug_argv(werkzeug, *SIGNTOOL_VERIFY, p["signiert"]), capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SigningError("signtool_start", "signtool verify nicht ausführbar (%s)" % exc.__class__.__name__) from None
    ausgabe = parse_signtool(_dekodiere(r.stdout) + "\n" + _dekodiere(r.stderr))
    if ausgabe["fake"] and os.environ.get("SIGN_TROCKENLAUF") != "1":
        raise SigningError("fake_signtool", "Prüfwerkzeug ist das Trockenlauf-Fake – außerhalb des Trockenlaufs verboten")
    blatt = bewerte_signtool(ausgabe, r.returncode, herausgeber, authenticode)
    git_sha = os.environ.get("GITHUB_SHA", "")
    if not GIT_SHA_RE.match(git_sha):
        raise SigningError("umgebung_fehlt", "GITHUB_SHA fehlt (Commit des getesteten Stands)")
    trocken = ausgabe["fake"]
    release = pruefe_release_body({
        "version": e["version"], "git_sha": git_sha, "build_id": e["build_id"], "kanal": e["kanal"],
        "artefakte": [{"name": e["asset"], "sha256": sha_s, "groesse": len(signiert)}],
        "vorgaenger_id": e["vorgaenger_id"], "erstausrollung": e["erstausrollung"], "symbole": [],
        "notiz": ("TROCKENLAUF – nicht ausrollen" if trocken else "Signiert mit Microsoft Artifact Signing")
        + "; Ablage %s/signed; remote_e2e_fps %g" % (e["build_id"], qualitaet["remote_e2e_fps"])})
    nachweis = pruefe_nachweis_body({
        "artefakt": e["asset"], "sha256": sha_s, "status": "ungueltig" if trocken else "gueltig",
        "aussteller": ("%s; Inhaber %s" % (blatt["ausgestellt_von"], blatt["ausgestellt_fuer"]))[:200],
        "zeitstempel": True,
        "werkzeug": ("signtool verify /pa /tw /v" + (" – TROCKENLAUF mit Fake-Werkzeug, keine echte Signatur" if trocken else ""))[:200],
        "lauf_url": _lauf_url(os.environ)})
    pruefungen = ["qualitaet", "sha256_unsigniert", "zertifikatstabelle", "inhalt_unveraendert", "build_id",
                  "signtool_verify_pa", "kette_nicht_selbstsigniert", "aussteller_artifact_signing", "herausgeber",
                  "zeitstempel", "authenticode_hash"]
    bericht = {"format": BERICHT_FORMAT, "asset": e["asset"], "build_id": e["build_id"],
               "sha256_unsigniert": e["sha256"], "sha256_signiert": sha_s, "groesse_unsigniert": len(unsigniert),
               "groesse_signiert": len(signiert), "auffuellbytes": auffuellung,
               "zertifikatstabelle": {"offset": lay_s["sec_va"], "laenge": lay_s["sec_size"]},
               "authenticode_sha256": authenticode, "herausgeber": blatt["ausgestellt_fuer"],
               "aussteller": blatt["ausgestellt_von"], "zeitstempel": ausgabe["zeitstempel"],
               "kette": [{k: z.get(k, "") for k in ("ausgestellt_fuer", "ausgestellt_von", "ablauf", "sha1")} for z in ausgabe["kette"]],
               "zeitstempel_kette": [{k: z.get(k, "") for k in ("ausgestellt_fuer", "ausgestellt_von")} for z in ausgabe["zeitstempel_kette"]],
               "werkzeug": "signtool " + " ".join(SIGNTOOL_VERIFY) + (" (Trockenlauf-Fake)" if trocken else ""),
               "trockenlauf": trocken, "pruefungen": {name: True for name in pruefungen}, "qualitaet": qualitaet,
               "git_sha": git_sha, "lauf_url": nachweis["lauf_url"], "geprueft_am": _jetzt(), "ablage": None}
    os.makedirs(p["nachweis"], exist_ok=True)
    for name, obj in zip(NACHWEIS_DATEIEN, (release, nachweis, bericht)):
        _schreibe_json(os.path.join(p["nachweis"], name), obj)
    _ausgabe("installer", p["signiert"])
    _ausgabe("nachweis_ordner", p["nachweis"])
    _ausgabe("sha256_signiert", sha_s)
    _zusammenfassung("Nachprüfung bestanden" + (" (TROCKENLAUF – Nachweis absichtlich ungültig)" if trocken else ""), [
        ("SHA-256 (signiert)", sha_s), ("Inhalt", "unverändert, %d Auffüllbytes + Zertifikatstabelle" % auffuellung),
        ("signtool verify /pa /tw /v", "fehlerfrei"), ("Inhaber", blatt["ausgestellt_fuer"]),
        ("Aussteller", blatt["ausgestellt_von"]), ("Zeitstempel", ausgabe["zeitstempel"]),
        ("Authenticode-Hash", authenticode), ("Qualität", "bestanden, remote_e2e_fps %g" % qualitaet["remote_e2e_fps"]),
        ("Nachweis-Status", nachweis["status"])])


def _lies_bericht(p):
    pfad = os.path.join(p["nachweis"], "signatur-bericht.json")
    if not os.path.isfile(pfad):
        raise SigningError("nachweis_fehlt", "Signaturbericht fehlt – Nachprüfung nicht gelaufen")
    with open(pfad, encoding="utf-8") as fh:
        return pfad, json.load(fh)


def cmd_hochladen():
    e = lese_eingaben()
    p = _pfade(e)
    _repo_pruefen()
    _pfad, bericht = _lies_bericht(p)
    if (bericht.get("build_id"), bericht.get("sha256_unsigniert")) != (e["build_id"], e["sha256"]):
        raise SigningError("manifest_abweichung", "Signaturbericht passt nicht zu den Eingaben")
    data = _lies(p["signiert"])
    sha_s = hashlib.sha256(data).hexdigest()
    if sha_s != bericht.get("sha256_signiert"):
        raise SigningError("datei_veraendert", "Signierter Installer nach der Nachprüfung verändert")
    _ablage().lege_ab(e["build_id"], "signed", data, sha_s)
    _zusammenfassung("Signierten Installer in der Ablage abgelegt", [
        ("Ablage", "%s/signed" % e["build_id"]), ("Datei", e["asset"]), ("Größe", "%d Bytes" % len(data)),
        ("X-Artifact-SHA256", sha_s)])


def cmd_ablage_pruefen():
    e = lese_eingaben()
    p = _pfade(e)
    _repo_pruefen()
    pfad, bericht = _lies_bericht(p)
    lokal = _lies(p["signiert"])
    sha_s = hashlib.sha256(lokal).hexdigest()
    if sha_s != bericht.get("sha256_signiert"):
        raise SigningError("datei_veraendert", "Signierter Installer nach der Nachprüfung verändert")
    ablage = _ablage()
    m = ablage.manifest(e["build_id"])
    pruefe_manifest(m, e["build_id"], "unsigned", e["sha256"], abweichung_code="ablage_abweichung")
    eintrag = pruefe_manifest(m, e["build_id"], "signed", sha_s, fehlt_code="upload_fehlt", abweichung_code="upload_digest")
    if eintrag["size"] != len(lokal):
        raise SigningError("upload_digest", "Größe des signierten Installers in der Ablage ≠ lokal")
    zurueck = ablage.lade(e["build_id"], "signed", MAX_GROESSE, fehlt_code="upload_fehlt")
    if hashlib.sha256(zurueck).hexdigest() != sha_s or zurueck != lokal:
        raise SigningError("upload_abweichung", "Erneut heruntergeladener signierter Installer ≠ geprüfte Datei")
    bericht["ablage"] = {"build_id": e["build_id"], "kind": "signed", "dateiname": e["asset"], "sha256": sha_s,
                         "groesse": len(lokal), "uploaded_at": _zeitpunkt(eintrag.get("uploaded_at"))}
    _schreibe_json(pfad, bericht)
    _zusammenfassung("Ablage geprüft", [("Manifest", "signed = SHA-256 (signiert) " + sha_s),
                                        ("Erneuter Download", "bitgleich, %d Bytes" % len(zurueck))])


BEFEHLE = {"eingaben": cmd_eingaben, "umgebung": cmd_umgebung, "qualitaet": cmd_qualitaet, "laden": cmd_laden,
           "vorpruefen": cmd_vorpruefen, "nachpruefen": cmd_nachpruefen, "hochladen": cmd_hochladen,
           "ablage-pruefen": cmd_ablage_pruefen}


def _annotation(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] not in BEFEHLE:
        print("Aufruf: artifact_signing.py {%s}" % "|".join(BEFEHLE), file=sys.stderr)
        return 2
    try:
        BEFEHLE[argv[0]]()
    except SigningError as exc:
        print("FEHLER [%s]: %s" % (exc.code, exc.meldung), file=sys.stderr)
        if github_pruefungen():
            print("::error title=Signaturpfad abgebrochen (%s)::%s" % (exc.code, _annotation(exc.meldung)))
        _zusammenfassung("Abbruch in „%s“" % argv[0], [("Code", exc.code), ("Meldung", exc.meldung)])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
