#!/usr/bin/env python3
"""Lokaler Trockenlauf des Signaturpfads – führt die Jobs vorpruefung und signieren aus
.github/workflows/sign-cockpit.yml so aus, wie der Runner sie ausführen würde, ohne Azure und ohne Netz.

- run-Schritte: echte Aufrufe von tools/signing/artifact_signing.py mit der env aus dem Workflow (Ausdrücke
  ${{ inputs.* }}, ${{ vars.* }}, ${{ secrets.SIGNING_STORAGE_TOKEN }}, ${{ steps.*.outputs.* }}, ${{ github.token }}
  werden wie auf GitHub aufgelöst).
- Ablage: Fake der privaten Signatur-Artefaktablage (fake_storage.py, gleicher Vertrag, Zustand in einem Ordner),
  eingehängt über SIGN_STORAGE_FAKE – derselbe Client-Code wie produktiv, nur der Transport ist ersetzt.
- uses-Schritte werden simuliert: checkout (Arbeitsbaum), azure/login (Pflichtwerte), actions/upload-artifact
  (ZIP-Digest wie v7.0.2) und azure/artifact-signing-action nach dem Quelltext von v2.0.0 + PowerShell-Modul
  ArtifactSigning 0.1.8: metadata.json, signtool-Argumente mit Anführungszeichen je Pfad, Start-Process-Zeile,
  Zerlegung nach Windows-Regeln, Exit 0/2 = Erfolg.
- Werkzeuge: fake_signtool.py und fake_gh.py, aufgerufen über Pfade mit Leerzeichen und Klammern.
- Szenarien: Erfolg (privates und öffentliches Repository) und jeder Abbruchgrund; erwartet werden Abbruch im
  richtigen Schritt mit dem richtigen Fehlercode, keine Signatur vor bestandener Vorprüfung, kein Ablage-Upload ohne
  gültige Nachprüfung und nie ein Installer als GitHub-Artefakt.

Aufruf: python3 tools/signing/trockenlauf.py [--bericht datei.json] [--szenario NAME …] [--behalten]
Exit 0 nur, wenn jedes Szenario genau das erwartete Ergebnis liefert.
"""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import artifact_signing as sig  # noqa: E402
import fake_signtool  # noqa: E402
import fake_storage  # noqa: E402
import workflow_check  # noqa: E402

HELFER = os.path.join(HERE, "artifact_signing.py")
REPO = workflow_check.REPO
WORKFLOW = workflow_check.WORKFLOW
BUILD_ID = "20261109-120000"
GIT_SHA = "0123456789abcdef0123456789abcdef01234567"
REPO_NAME = "trockenlauf/cockpit-signing"
SERVER = "https://github.example.invalid"
ABLAGE_TOKEN = "trockenlauf-ablage-kein-geheimnis-0001"     # Testwert der Fake-Ablage, kein echtes Token
EINGABEN = {"build_id": BUILD_ID, "sha256": None, "version": "2026.11.1-trockenlauf", "kanal": "pilot",
            "vorgaenger_id": "", "erstausrollung": True}
VARIABLEN = {"AZURE_CLIENT_ID": "trockenlauf-client", "AZURE_TENANT_ID": "trockenlauf-mandant",
             "AZURE_SUBSCRIPTION_ID": "trockenlauf-abonnement",
             "ARTIFACT_SIGNING_ENDPOINT": "https://weu.codesigning.azure.net",
             "ARTIFACT_SIGNING_ACCOUNT": "trockenlaufkonto", "ARTIFACT_SIGNING_PROFILE": "trockenlauf-profil",
             "ARTIFACT_SIGNING_PUBLISHER": fake_signtool.STANDARD_HERAUSGEBER}
QUALITAET = {"build_id": BUILD_ID, "bestanden": True, "remote_e2e_fps": 15.2, "version": "2026.11.1-trockenlauf",
             "suiten": {"python": "bestanden", "js-syntax": "bestanden", "secret-scan": "bestanden"}}
# action.yml v2.0.0: Standardwerte der exclude-Eingaben; Metadata.psm1: Reihenfolge der ExcludeCredentials
AUSSCHLUSS = (("exclude-environment-credential", "false", "EnvironmentCredential"),
              ("exclude-workload-identity-credential", "true", "WorkloadIdentityCredential"),
              ("exclude-managed-identity-credential", "true", "ManagedIdentityCredential"),
              ("exclude-shared-token-cache-credential", "true", "SharedTokenCacheCredential"),
              ("exclude-visual-studio-credential", "true", "VisualStudioCredential"),
              ("exclude-visual-studio-code-credential", "true", "VisualStudioCodeCredential"),
              ("exclude-azure-cli-credential", "false", "AzureCliCredential"),
              ("exclude-azure-powershell-credential", "true", "AzurePowerShellCredential"),
              ("exclude-azure-developer-cli-credential", "true", "AzureDeveloperCliCredential"),
              ("exclude-interactive-browser-credential", "true", "InteractiveBrowserCredential"))
SIMULIERTE_SIGNIER_EINGABEN = {"endpoint", "signing-account-name", "certificate-profile-name", "files", "file-digest",
                               "timestamp-rfc3161", "timestamp-digest", "description", "cache-dependencies"} | {a[0] for a in AUSSCHLUSS}
SCHRITTE_VOR_SIGNATUR = ("eingaben", "umgebung", "qualitaet", "laden", "vorpruefen")
TOKEN_CODES = ("storage_token", "storage_token_fehlt", "storage_token_format")


class TrockenlaufFehler(Exception):
    pass


def quality_bytes(**aenderung):
    q = dict(QUALITAET)
    for k, v in aenderung.items():
        if v is None:
            q.pop(k, None)
        else:
            q[k] = v
    return json.dumps(q, ensure_ascii=False, sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------- synthetischer NSIS-Installer

def _ausrichten(n, a):
    return (n + a - 1) // a * a


def _vblock(schluessel, wert=b"", kinder=b"", typ=0, wertlaenge=None):
    k = (schluessel + "\0").encode("utf-16-le")
    rumpf = k + b"\0" * ((-(6 + len(k))) % 4) + wert
    if kinder:
        rumpf += b"\0" * ((-(6 + len(rumpf))) % 4) + kinder
    if wertlaenge is None:
        wertlaenge = len(wert) // 2 if typ == 1 else len(wert)
    return struct.pack("<HHH", 6 + len(rumpf), wertlaenge, typ) + rumpf


def _verkette(bloecke):
    return b"".join(b + b"\0" * ((-len(b)) % 4) for b in bloecke)


def versionsressource(werte):
    texte = _verkette([_vblock(k, (v + "\0").encode("utf-16-le"), typ=1, wertlaenge=len(v) + 1) for k, v in werte.items()])
    sfi = _vblock("StringFileInfo", kinder=_verkette([_vblock("040704b0", kinder=texte, typ=1)]), typ=1)
    vfi = _vblock("VarFileInfo", kinder=_verkette([_vblock("Translation", struct.pack("<HH", 0x0407, 0x04B0))]), typ=1)
    fest = struct.pack("<13I", 0xFEEF04BD, 0x00010000, 0x00010001, 0, 0x00010001, 0, 0x3F, 0, 0x00040004, 1, 0, 0, 0)
    return _vblock("VS_VERSION_INFO", fest, kinder=_verkette([sfi, vfi]))


def _ressourcen(rva, vinfo):
    ordner = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    return (ordner + struct.pack("<II", sig.RT_VERSION, 0x80000000 | 24) + ordner + struct.pack("<II", 1, 0x80000000 | 48)
            + ordner + struct.pack("<II", 0x0407, 72) + struct.pack("<IIII", rva + 88, len(vinfo), 0, 0) + vinfo)


def baue_installer(build_id=BUILD_ID, *, produkt=sig.PRODUKT, hersteller=sig.HERSTELLER, build_id_intern=None,
                   nsis=True, pe32plus=False, nutzlast=40003, saat=7, vorsigniert=False):
    """Kleiner, aber strukturell echter PE mit Versionsressource wie installer.nsi und NSIS-firstheader im Overlay."""
    bid = build_id_intern or build_id
    vinfo = versionsressource({"CompanyName": hersteller, "FileDescription": "Fernwartungszugang (Trockenlauf)",
                               "FileVersion": bid, "BuildId": bid, "LegalCopyright": hersteller, "ProductName": produkt})
    fa, sa, kopf, pe = 0x200, 0x1000, 0x400, 0x80
    text_rva, rsrc_rva = 0x1000, 0x2000
    text = (b"\x55\x8b\xec\x33\xc0\x5d\xc3\x90" * 64).ljust(fa, b"\0")
    rsrc = _ressourcen(rsrc_rva, vinfo)
    rsrc_roh = rsrc.ljust(_ausrichten(len(rsrc), fa), b"\0")
    opt_groesse = 240 if pe32plus else 224
    b = bytearray(kopf)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, pe)
    b[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", b, pe + 4, 0x8664 if pe32plus else 0x14C, 2, 0, 0, 0, opt_groesse,
                     0x0022 if pe32plus else 0x0102)
    opt = pe + 24
    if pe32plus:
        struct.pack_into("<HBBIIIII", b, opt, 0x20B, 14, 0, len(text), len(rsrc_roh), 0, text_rva, text_rva)
        struct.pack_into("<Q", b, opt + 24, 0x140000000)
        struct.pack_into("<QQQQII", b, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 112
    else:
        struct.pack_into("<HBBIIIIII", b, opt, 0x10B, 14, 0, len(text), len(rsrc_roh), 0, text_rva, text_rva, rsrc_rva)
        struct.pack_into("<I", b, opt + 28, 0x400000)
        struct.pack_into("<IIIIII", b, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 96
    struct.pack_into("<IIHHHHHHIII", b, opt + 32, sa, fa, 6, 0, 0, 0, 6, 0, 0, rsrc_rva + _ausrichten(len(rsrc), sa), kopf)
    struct.pack_into("<HH", b, opt + 68, 2, 0x8140)
    struct.pack_into("<II", b, dd + 16, rsrc_rva, len(rsrc))
    sh = opt + opt_groesse
    struct.pack_into("<8sIIIIIIHHI", b, sh, b".text", fa, text_rva, len(text), kopf, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", b, sh + 40, b".rsrc", len(rsrc), rsrc_rva, len(rsrc_roh), kopf + len(text), 0, 0, 0, 0,
                     0x40000040)
    zufall = random.Random(saat)
    daten = bytes(zufall.getrandbits(8) for _ in range(nutzlast))
    if nsis:
        overlay = struct.pack("<II", 0, 0xDEADBEEF) + b"NullsoftInst" + struct.pack("<II", 0x1000, 28 + nutzlast + 4) + daten
    else:
        overlay = daten + b"\0" * 28
    roh = bytes(b) + text + rsrc_roh + overlay + struct.pack("<I", 0x1234ABCD)
    if vorsigniert:
        roh = fake_signtool.signiere_bytes(roh, {"kette": fake_signtool.kette_fuer("ok", "Alt GmbH"),
                                                 "zeitstempel": fake_signtool.ZEITSTEMPEL})
    return roh


# ---------------------------------------------------------------- Windows-Argumente (Start-Process → signtool)

def windows_argv(zeile):
    """Zerlegung einer Kommandozeile nach den Regeln von CommandLineToArgvW/MSVCRT."""
    args, aktuell, in_quotes, belegt, i = [], [], False, False, 0
    while i < len(zeile):
        c = zeile[i]
        if c == "\\":
            j = i
            while j < len(zeile) and zeile[j] == "\\":
                j += 1
            if j < len(zeile) and zeile[j] == '"':
                aktuell.append("\\" * ((j - i) // 2))
                if (j - i) % 2:
                    aktuell.append('"')
                    j += 1
                i, belegt = j, True
                continue
            aktuell.append("\\" * (j - i))
            i, belegt = j, True
            continue
        if c == '"':
            if in_quotes and zeile[i + 1:i + 2] == '"':
                aktuell.append('"')
                i += 2
                continue
            in_quotes, belegt, i = not in_quotes, True, i + 1
            continue
        if c in " \t" and not in_quotes:
            if belegt:
                args.append("".join(aktuell))
                aktuell, belegt = [], False
            i += 1
            continue
        aktuell.append(c)
        belegt, i = True, i + 1
    if belegt:
        args.append("".join(aktuell))
    return args


# ---------------------------------------------------------------- Lauf-Kontext

class Szenario:
    def __init__(self, name, beschreibung, erwartet, **aenderungen):
        self.name, self.beschreibung, self.erwartet, self.a = name, beschreibung, erwartet, aenderungen


SZENARIEN = [
    Szenario("erfolg", "Gültiger Installer: Qualität, Vorprüfung, Signatur, Nachprüfung, Ablage-Upload mit Hashprüfung", None),
    Szenario("erfolg_oeffentlich", "Öffentliches Repository ist erlaubt (Installer nur in der privaten Ablage)", None,
             repository={"private": False, "visibility": "public"}),
    Szenario("eingabe_build_id", "Build-ID nicht im Format JJJJMMTT-HHMMSS", ("vorpruefung", "eingaben", "eingabe_build_id"),
             eingaben={"build_id": "2026-11-09"}),
    Szenario("eingabe_sha256", "SHA-256 kein Hexwert", ("vorpruefung", "eingaben", "eingabe_sha256"),
             eingaben={"sha256": "kein-hash"}),
    Szenario("eingabe_rollback", "Vorgänger und Erstausrollung zugleich", ("vorpruefung", "eingaben", "eingabe_rollback"),
             eingaben={"vorgaenger_id": "R-0123456789ab", "erstausrollung": True}),
    Szenario("falscher_zweig", "Lauf nicht von main", ("vorpruefung", "eingaben", "eingabe_ref"), ref="refs/heads/feature"),
    Szenario("ueberschreibung_auf_github", "Werkzeug-/Ablage-Überschreibung auf GitHub-Runner",
             ("vorpruefung", "eingaben", "override_verboten"), runner_environment="github-hosted"),
    Szenario("ueberschreibung_self_hosted", "Werkzeug-Überschreibung auf selbst gehostetem Runner (GITHUB_ACTIONS=true)",
             ("vorpruefung", "eingaben", "override_verboten"), github_actions=True),
    Szenario("repo_unbekannt", "Ereignis ohne repository.private", ("vorpruefung", "umgebung", "repo_unbekannt"),
             repository={"private": None}),
    Szenario("repo_fremd", "repository.full_name ≠ GITHUB_REPOSITORY", ("vorpruefung", "umgebung", "repo_unbekannt"),
             repository={"full_name": "fremd/cockpit-signing"}),
    Szenario("repo_widerspruechlich", "private=false, visibility=private", ("vorpruefung", "umgebung", "repo_unbekannt"),
             repository={"private": False, "visibility": "private"}),
    Szenario("umgebung_admin_bypass", "Administratoren dürfen die Freigabe umgehen",
             ("vorpruefung", "umgebung", "umgebung_admin_bypass"), umgebung={"can_admins_bypass": True}),
    Szenario("umgebung_fehlt", "Environment release-signing nicht angelegt", ("vorpruefung", "umgebung", "umgebung_fehlt"),
             gh_modus="umgebung-fehlt"),
    Szenario("umgebung_ohne_reviewer", "Environment ohne Pflicht-Reviewer", ("vorpruefung", "umgebung", "umgebung_ungeschuetzt"),
             umgebung={"protection_rules": [{"type": "branch_policy"}]}),
    Szenario("umgebung_alle_zweige", "Environment für alle Zweige offen", ("vorpruefung", "umgebung", "umgebung_zweige"),
             umgebung={"deployment_branch_policy": None}),
    Szenario("umgebung_fremder_zweig", "Zweigregel erlaubt mehr als main", ("vorpruefung", "umgebung", "umgebung_zweige"),
             zweige={"branch_policies": [{"name": "*", "type": "branch"}]}),
    Szenario("token_fehlt", "Repo-Secret SIGNING_STORAGE_TOKEN leer", ("vorpruefung", "qualitaet", "storage_token_fehlt"),
             secrets={"SIGNING_STORAGE_TOKEN": ""}),
    Szenario("token_falsch", "Ablage lehnt das Token ab (401)", ("vorpruefung", "qualitaet", "storage_token"),
             secrets={"SIGNING_STORAGE_TOKEN": "trockenlauf-falsches-token-0002"}),
    Szenario("ablage_ohne_token", "Ablage serverseitig ohne Token (503)", ("vorpruefung", "qualitaet", "storage_nicht_konfiguriert"),
             ablage={"token": None}),
    Szenario("build_fehlt", "Build nicht in der Ablage (404)", ("vorpruefung", "qualitaet", "storage_fehlt"),
             ablage={"ohne": ["unsigned", "quality"]}),
    Szenario("quality_fehlt", "Kein Qualitätsnachweis zum Build", ("vorpruefung", "qualitaet", "quality_fehlt"),
             ablage={"ohne": ["quality"]}),
    Szenario("quality_nicht_bestanden", "quality.json mit bestanden=false", ("vorpruefung", "qualitaet", "quality_ungueltig"),
             ablage={"quality_roh": {"bestanden": False}}),
    Szenario("quality_ohne_fps", "quality.json ohne remote_e2e_fps", ("vorpruefung", "qualitaet", "quality_ungueltig"),
             ablage={"quality_roh": {"remote_e2e_fps": None}}),
    Szenario("quality_fremder_build", "quality.json eines anderen Builds", ("vorpruefung", "qualitaet", "quality_ungueltig"),
             ablage={"quality_roh": {"build_id": "20261108-235959"}}),
    Szenario("quality_beschaedigt", "Download von quality.json ≠ Manifest", ("vorpruefung", "qualitaet", "quality_abweichung"),
             ablage={"stoerung": {"get_falsch": ["quality"]}}),
    Szenario("unsigned_fehlt", "Qualität vorhanden, Installer fehlt", ("vorpruefung", "laden", "asset_fehlt"),
             ablage={"ohne": ["unsigned"]}),
    Szenario("manifest_sha_abweichend", "Erwarteter SHA-256 ≠ Hash in der Ablage", ("vorpruefung", "laden", "digest_abweichung"),
             sha_falsch=True),
    Szenario("download_beschaedigt", "Download ≠ Manifest", ("vorpruefung", "laden", "download_abweichung"),
             ablage={"stoerung": {"get_falsch": ["unsigned"]}}),
    Szenario("signiert_vorhanden", "Build wurde schon signiert", ("vorpruefung", "laden", "signiert_vorhanden"),
             ablage={"signed_vorhanden": True}),
    Szenario("build_id_abweichend", "Versionsressource trägt andere Build-ID", ("vorpruefung", "vorpruefen", "build_id_abweichung"),
             installer={"build_id_intern": "20261108-235959"}),
    Szenario("kein_nsis", "PE ohne NSIS-Daten (an der Ablage-Prüfung vorbei abgelegt)", ("vorpruefung", "vorpruefen", "kein_nsis"),
             installer={"nsis": False}, ablage={"roh": True}),
    Szenario("fremdes_produkt", "Fremder Installer", ("vorpruefung", "vorpruefen", "hersteller_abweichung"),
             installer={"produkt": "Fremdprodukt"}),
    Szenario("bereits_signiert", "Eingang trägt schon eine Signatur", ("vorpruefung", "vorpruefen", "bereits_signiert"),
             installer={"vorsigniert": True}),
    Szenario("austausch_nach_vorpruefung", "Installer nach der Vorprüfung per replace=1 ersetzt",
             ("signieren", "laden", "digest_abweichung"), zwischen="tausch"),
    Szenario("geloescht_nach_vorpruefung", "Build nach der Vorprüfung gelöscht", ("signieren", "qualitaet", "storage_fehlt"),
             zwischen="loeschen"),
    Szenario("signtool_fehler", "Signierwerkzeug bricht ab (Exit 1)", ("signieren", "signieren", "action"), signtool="fehler"),
    Szenario("ohne_signatur", "Signierwerkzeug meldet Erfolg ohne zu signieren", ("signieren", "nachpruefen", "signatur_fehlt"),
             signtool="ohne-signatur"),
    Szenario("ohne_signatur_warnung", "Exit 2 (Warnung) gilt dem Modul als Erfolg", ("signieren", "nachpruefen", "signatur_fehlt"),
             signtool="warnung-ohne-signatur"),
    Szenario("selbstsigniert", "Selbstsigniertes Zertifikat", ("signieren", "nachpruefen", "selbstsigniert"),
             signtool="selbstsigniert"),
    Szenario("ohne_zeitstempel", "Kein Zeitstempel (signtool /tw: Warnung)", ("signieren", "nachpruefen", "signtool_verify"),
             signtool="ohne-zeitstempel"),
    Szenario("ohne_zeitstempel_exit0", "Kein Zeitstempel, Prüfung ohne Warnung", ("signieren", "nachpruefen", "zeitstempel_fehlt"),
             signtool="ohne-zeitstempel-exit0"),
    Szenario("falscher_herausgeber", "Fremder Zertifikatsinhaber", ("signieren", "nachpruefen", "herausgeber_abweichung"),
             signtool="falscher-herausgeber"),
    Szenario("fremde_ca", "Zertifikat nicht von Artifact Signing", ("signieren", "nachpruefen", "aussteller_abweichung"),
             signtool="fremde-ca"),
    Szenario("inhalt_manipuliert", "Inhalt beim Signieren verändert", ("signieren", "nachpruefen", "inhalt_geaendert"),
             signtool="manipulieren"),
    Szenario("verify_abgelehnt", "Kette endet in nicht vertrauenswürdiger Wurzel", ("signieren", "nachpruefen", "signtool_verify"),
             signtool="verify-abgelehnt"),
    Szenario("herausgeber_variable_fehlt", "ARTIFACT_SIGNING_PUBLISHER leer", ("signieren", "nachpruefen", "herausgeber_fehlt"),
             vars={"ARTIFACT_SIGNING_PUBLISHER": ""}),
    Szenario("fake_ausserhalb_trockenlauf", "Fake-signtool ohne Trockenlauf-Kennung", ("signieren", "nachpruefen", "fake_signtool"),
             trockenlauf_kennung=False),
    Szenario("upload_konflikt", "signed existiert bereits (409, kein Überschreiben)", ("signieren", "hochladen", "storage_konflikt"),
             ablage={"stoerung": {"status": {"PUT signed": 409}}}),
    Szenario("upload_zu_gross", "Ablage meldet 413", ("signieren", "hochladen", "storage_zu_gross"),
             ablage={"stoerung": {"status": {"PUT signed": 413}}}),
    Szenario("upload_abgelehnt", "Ablage meldet 422 (Hash/Format)", ("signieren", "hochladen", "storage_abgelehnt"),
             ablage={"stoerung": {"status": {"PUT signed": 422}}}),
    Szenario("upload_digest_falsch", "Manifest-Hash von signed ≠ geprüfter SHA-256", ("signieren", "ablage_pruefen", "upload_digest"),
             ablage={"stoerung": {"manifest_sha": {"signed": "f" * 64}}}),
    Szenario("upload_download_beschaedigt", "Erneuter Download ≠ geprüfte Datei", ("signieren", "ablage_pruefen", "upload_abweichung"),
             ablage={"stoerung": {"get_falsch": ["signed"]}}),
]


def _wrapper(pfad, ziel):
    os.makedirs(os.path.dirname(pfad), exist_ok=True)
    with open(pfad, "w", encoding="utf-8") as fh:
        fh.write("import runpy, sys\nsys.path.insert(0, %r)\nsys.argv[0] = %r\nrunpy.run_path(%r, run_name='__main__')\n"
                 % (HERE, ziel, ziel))
    return pfad


class Lauf:
    def __init__(self, szenario, basis):
        self.s, self.basis = szenario, basis
        a = szenario.a
        os.makedirs(basis, exist_ok=True)
        self.signtool = _wrapper(os.path.join(basis, "Program Files (x86)", "Windows Kits", "10", "bin", "10.0.26100.0",
                                              "x64", "signtool.py"), os.path.join(HERE, "fake_signtool.py"))
        self.gh = _wrapper(os.path.join(basis, "GitHub CLI", "gh.py"), os.path.join(HERE, "fake_gh.py"))
        self.dlib_ordner = os.path.join(basis, "AppData Local", "ArtifactSigning", "Microsoft.ArtifactSigning.Client 1.0.128",
                                        "bin", "x64")
        os.makedirs(self.dlib_ordner, exist_ok=True)
        self.dlib = os.path.join(self.dlib_ordner, "Azure.CodeSigning.Dlib.dll")
        open(self.dlib, "wb").close()
        self.protokoll_signtool = os.path.join(basis, "signtool-protokoll.jsonl")
        self.protokoll_gh = os.path.join(basis, "gh-protokoll.jsonl")
        self.installer = baue_installer(**a.get("installer", {}))
        self.sha256 = hashlib.sha256(self.installer).hexdigest()
        self.eingaben = dict(EINGABEN, sha256=self.sha256)
        if a.get("sha_falsch"):
            self.eingaben["sha256"] = hashlib.sha256(b"anderer Build").hexdigest()
        self.eingaben.update(a.get("eingaben", {}))
        self.vars = dict(VARIABLEN, **a.get("vars", {}))
        self.secrets = dict({"SIGNING_STORAGE_TOKEN": ABLAGE_TOKEN}, **a.get("secrets", {}))
        self.uploads, self.jobs, self.aktion_signieren = [], {}, None
        umgebung = {"name": sig.UMGEBUNG, "can_admins_bypass": False, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                    "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False,
                                          "reviewers": [{"type": "User", "reviewer": {"login": "trockenlauf-pruefer"}}]},
                                         {"type": "branch_policy"}]}
        umgebung.update(a.get("umgebung", {}))
        zweige = {"total_count": 1, "branch_policies": [{"name": sig.ZWEIG, "type": "branch"}]}
        zweige.update(a.get("zweige", {}))
        repository = {"full_name": REPO_NAME, "private": True, "visibility": "private"}
        for k, v in a.get("repository", {}).items():
            if v is None:
                repository.pop(k, None)
            else:
                repository[k] = v
        ereignis = {"ref": sig.REF_ERLAUBT, "inputs": dict(self.eingaben), "repository": repository}
        self.umgebung_json, self.zweige_json = os.path.join(basis, "umgebung.json"), os.path.join(basis, "zweige.json")
        self.ereignis_json = os.path.join(basis, "ereignis.json")
        for pfad, obj in ((self.umgebung_json, umgebung), (self.zweige_json, zweige), (self.ereignis_json, ereignis)):
            with open(pfad, "w", encoding="utf-8") as fh:
                json.dump(obj, fh)
        self.ablage_ordner = os.path.join(basis, "Ablage (privat)")
        self._ablage_einrichten(a.get("ablage", {}))

    # ---------- Fake-Ablage: Ausgangszustand wie nach vorbereiten.py (unsigned + quality per PUT)
    def _ablage_einrichten(self, ab):
        token = ab["token"] if "token" in ab else ABLAGE_TOKEN
        self.ablage = fake_storage.FakeAblage.einrichten(self.ablage_ordner, token)
        self.quality = quality_bytes(**ab.get("quality_roh", {}))
        ohne = ab.get("ohne", ())
        if "unsigned" not in ohne:
            self.ablage_put("unsigned", self.installer, roh=ab.get("roh"))
        if "quality" not in ohne:
            self.ablage_put("quality", self.quality, roh="quality_roh" in ab)
        if ab.get("signed_vorhanden"):
            self.ablage_put("signed", fake_signtool.signiere_bytes(self.installer, {"kette": [], "zeitstempel": None}))
        self.ablage.aendere_konfig(stoerung=ab.get("stoerung", {}))

    def ablage_put(self, kind, daten, roh=False, replace=False):
        if roh or not self.ablage.konfig().get("token"):
            self.ablage.roh_ablegen(BUILD_ID, kind, daten)
            return
        status, _ = self.ablage.anfrage("PUT", "%s/%s/%s%s" % (sig.STORAGE_BASIS, BUILD_ID, kind, "?replace=1" if replace else ""),
                                        {"Authorization": "Bearer " + ABLAGE_TOKEN,
                                         "X-Artifact-SHA256": hashlib.sha256(daten).hexdigest()}, daten)
        if status != 201:
            raise TrockenlaufFehler("Ablage-Einrichtung %s: HTTP %d" % (kind, status))

    def ablage_workflow(self):
        """Anfragen der Workflow-Schritte an die Ablage (ohne Einrichtung und Eingriffe des Trockenlaufs)."""
        return [p for p in self.ablage.protokoll() if p["quelle"] == "workflow"]

    # ---------- Ausdrücke wie auf GitHub
    def aufloesen(self, wert, ausgaben):
        if isinstance(wert, bool):
            return "true" if wert else "false"
        if not isinstance(wert, str):
            return str(wert)

        def ersetze(m):
            a = m.group(1).strip()
            for muster, quelle in ((r"inputs\.([a-z0-9_]+)", self.eingaben), (r"vars\.([A-Z0-9_]+)", self.vars),
                                   (r"secrets\.([A-Z0-9_]+)", self.secrets)):
                t = re.fullmatch(muster, a)
                if t:
                    return self.aufloesen(quelle.get(t.group(1), ""), ausgaben)
            t = re.fullmatch(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", a)
            if t:
                return ausgaben.get(t.group(1), {}).get(t.group(2), "")
            if a == "github.token":
                return "trockenlauf-ohne-token"
            raise TrockenlaufFehler("Ausdruck im Trockenlauf nicht unterstützt: " + a)
        return re.sub(r"\$\{\{(.*?)\}\}", ersetze, wert)

    def umgebung(self, job, runner_temp, ausgabe_datei, zusammenfassung, extra):
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if k in os.environ}
        # Kein GITHUB_ACTIONS: auf echten Runnern sind Fake-Werkzeuge verboten; GitHub-Prüfungen per Schalter.
        env.update({"PYTHONIOENCODING": "utf-8", "LANG": "C.UTF-8", "SIGN_GITHUB_SIMULATION": "1", "RUNNER_TEMP": runner_temp,
                    "GITHUB_OUTPUT": ausgabe_datei, "GITHUB_STEP_SUMMARY": zusammenfassung, "GITHUB_WORKSPACE": REPO,
                    "GITHUB_REPOSITORY": REPO_NAME, "GITHUB_SHA": GIT_SHA, "GITHUB_REF": self.s.a.get("ref", sig.REF_ERLAUBT),
                    "GITHUB_RUN_ID": "4711", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SERVER_URL": SERVER,
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_EVENT_PATH": self.ereignis_json,
                    "RUNNER_OS": "Windows" if job == "signieren" else "Linux",
                    # Maschine des Trockenlaufs: Fake-Werkzeuge und Fake-Ablage statt gh/signtool/HTTPS
                    "SIGN_GH": self.gh, "SIGN_SIGNTOOL": self.signtool, "SIGN_STORAGE_FAKE": self.ablage_ordner,
                    "FAKE_GH_PROTOKOLL": self.protokoll_gh, "FAKE_GH_UMGEBUNG": self.umgebung_json,
                    "FAKE_GH_ZWEIGE": self.zweige_json, "FAKE_GH_MODUS": self.s.a.get("gh_modus", "ok"),
                    "FAKE_SIGNTOOL_PROTOKOLL": self.protokoll_signtool, "FAKE_SIGNTOOL_MODUS": self.s.a.get("signtool", "ok")})
        if self.s.a.get("trockenlauf_kennung", True):
            env["SIGN_TROCKENLAUF"] = "1"
        if self.s.a.get("runner_environment"):
            env["RUNNER_ENVIRONMENT"] = self.s.a["runner_environment"]
        if self.s.a.get("github_actions"):
            env["GITHUB_ACTIONS"] = "true"
        env.update(extra)
        return env

    # ---------- Jobs
    def job(self, name, job):
        runner_temp = os.path.join(self.basis, "Runner Temp", name)
        os.makedirs(runner_temp, exist_ok=True)
        zusammenfassung = os.path.join(runner_temp, "_zusammenfassung.md")
        job_env = {k: self.aufloesen(v, {}) for k, v in (job.get("env") or {}).items()}
        ausgaben, schritte, fehlgeschlagen = {}, [], False
        for nr, schritt in enumerate(job["steps"], start=1):
            sid = schritt.get("id") or "schritt%d" % nr
            if fehlgeschlagen and schritt.get("if") != "always()":
                schritte.append({"id": sid, "name": schritt["name"], "status": "uebersprungen"})
                continue
            step_env = {k: self.aufloesen(v, ausgaben) for k, v in (schritt.get("env") or {}).items()}
            if "uses" in schritt:
                erg = self.action(schritt, ausgaben)
            else:
                ausgabe_datei = os.path.join(runner_temp, "_ausgabe_%d" % nr)
                open(ausgabe_datei, "w").close()
                erg = self.run(schritt["run"], self.umgebung(name, runner_temp, ausgabe_datei, zusammenfassung,
                                                             dict(job_env, **step_env)), ausgabe_datei)
            ausgaben[sid] = erg.get("ausgaben", {})
            schritte.append(dict(erg, id=sid, name=schritt["name"]))
            fehlgeschlagen = fehlgeschlagen or erg["status"] != "ok"
        with open(zusammenfassung, encoding="utf-8") if os.path.exists(zusammenfassung) else io.StringIO() as fh:
            text = fh.read()
        self.jobs[name] = {"status": "fehlgeschlagen" if fehlgeschlagen else "ok", "schritte": schritte,
                           "ausgaben": ausgaben, "runner_temp": runner_temp, "zusammenfassung": text}
        return self.jobs[name]

    def zwischen_den_jobs(self):
        """Eingriff zwischen Vorprüfung und Freigabe (z. B. Austausch des Installers in der Ablage)."""
        art = self.s.a.get("zwischen")
        if art == "tausch":
            self.ablage_put("unsigned", baue_installer(saat=99), replace=True)
        elif art == "loeschen":
            status, _ = self.ablage.anfrage("DELETE", "%s/%s" % (sig.STORAGE_BASIS, BUILD_ID),
                                            {"Authorization": "Bearer " + ABLAGE_TOKEN}, None)
            if status != 200:
                raise TrockenlaufFehler("Löschen in der Ablage: HTTP %d" % status)

    def run(self, run, env, ausgabe_datei):
        befehl = run.strip()
        if befehl == "az account clear":
            return {"status": "ok", "simuliert": "Azure-Sitzung beendet"}
        m = re.fullmatch(r"python3? tools/signing/artifact_signing\.py ([a-z-]+)", befehl)
        if not m:
            raise TrockenlaufFehler("run-Schritt nicht simulierbar: %r" % befehl)
        p = subprocess.run([sys.executable, HELFER, m.group(1)], cwd=REPO, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=180)
        with open(ausgabe_datei, encoding="utf-8") as fh:
            ausgaben = dict(z.split("=", 1) for z in fh.read().splitlines() if "=" in z)
        code = re.search(r"FEHLER \[([a-z0-9_]+)\]", p.stderr)
        return {"status": "ok" if p.returncode == 0 else "fehlgeschlagen", "exit": p.returncode, "befehl": m.group(1),
                "code": code.group(1) if code else None, "ausgaben": ausgaben, "stdout": p.stdout, "stderr": p.stderr}

    def action(self, schritt, ausgaben):
        name = schritt["uses"].split("@", 1)[0].lower()
        mit = {k: self.aufloesen(v, ausgaben) for k, v in (schritt.get("with") or {}).items()}
        if name == "actions/checkout":
            return {"status": "ok", "simuliert": "Arbeitsbaum"}
        if name == "azure/login":
            fehlt = [k for k in ("client-id", "tenant-id", "subscription-id") if not mit.get(k)]
            if fehlt:
                return {"status": "fehlgeschlagen", "code": "action", "meldung": "Login ohne " + ", ".join(fehlt)}
            return {"status": "ok", "simuliert": "OIDC-Anmeldung (kein Azure im Trockenlauf)"}
        if name == "azure/artifact-signing-action":
            return self.artifact_signing(mit)
        if name == "actions/upload-artifact":
            return self.upload(mit)
        raise TrockenlaufFehler("Action nicht simulierbar: " + name)

    def artifact_signing(self, mit):
        """azure/artifact-signing-action v2.0.0 → Invoke-ArtifactSigning (Modul 0.1.8) → signtool.exe."""
        unbekannt = set(mit) - SIMULIERTE_SIGNIER_EINGABEN
        if unbekannt:
            raise TrockenlaufFehler("Signier-Eingaben ohne Simulation: " + ", ".join(sorted(unbekannt)))
        if not mit.get("endpoint", "").strip():
            return {"status": "fehlgeschlagen", "code": "action", "meldung": "The 'endpoint' input is required."}
        if not mit.get("signing-account-name", "").strip():
            return {"status": "fehlgeschlagen", "code": "action", "meldung": "The 'signing-account-name' input is required."}
        dateien = [f.strip() for f in mit.get("files", "").replace("\n", ",").split(",") if f.strip()]
        if not dateien:
            return {"status": "fehlgeschlagen", "code": "action", "meldung": "No files were found to sign"}
        for f in dateien:
            if not os.path.isabs(f):
                return {"status": "fehlgeschlagen", "code": "action", "meldung": "The file path '%s' is not rooted." % f}
        metadaten = {"Endpoint": mit["endpoint"], "CodeSigningAccountName": mit["signing-account-name"],
                     "CertificateProfileName": mit.get("certificate-profile-name", ""),
                     "ExcludeCredentials": [n for k, standard, n in AUSSCHLUSS if mit.get(k, standard).lower() == "true"]}
        meta = os.path.join(self.dlib_ordner, "metadata.json")
        with open(meta, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(metadaten, separators=(",", ":")))
        args = ["sign", "/v", "/debug", "/fd", mit.get("file-digest", "SHA256")]
        if mit.get("timestamp-rfc3161", "http://timestamp.acs.microsoft.com"):
            args += ["/tr", mit.get("timestamp-rfc3161", "http://timestamp.acs.microsoft.com")]
        if mit.get("timestamp-digest", "SHA256"):
            args += ["/td", mit.get("timestamp-digest", "SHA256")]
        args += ["/dlib", '"%s"' % self.dlib, "/dmdf", '"%s"' % meta]
        if mit.get("description"):
            args += ["/d", '"%s"' % mit["description"]]
        args += ['"%s"' % f for f in dict.fromkeys(dateien)]
        zeile = " ".join(args)                      # Start-Process -ArgumentList verbindet mit Leerzeichen
        argv = windows_argv(zeile)
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT") if k in os.environ}
        env.update({"FAKE_SIGNTOOL_PROTOKOLL": self.protokoll_signtool, "FAKE_SIGNTOOL_MODUS": self.s.a.get("signtool", "ok"),
                    "PYTHONIOENCODING": "utf-8"})
        p = subprocess.run([sys.executable, self.signtool] + argv, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        self.aktion_signieren = {"kommandozeile": zeile, "argv": argv, "metadaten": metadaten, "exit": p.returncode}
        if p.returncode not in (0, 2):
            return {"status": "fehlgeschlagen", "code": "action", "meldung": "SignTool failed with exit code %d" % p.returncode,
                    "stdout": p.stdout}
        return {"status": "ok", "stdout": p.stdout}

    def upload(self, mit):
        pfad = mit.get("path", "")
        if mit.get("archive", "true").lower() == "false":
            return {"status": "fehlgeschlagen", "code": "action", "meldung": "archive: false (Rohdatei) ist hier verboten"}
        if not pfad or not os.path.exists(pfad):
            if mit.get("if-no-files-found", "warn") == "error":
                return {"status": "fehlgeschlagen", "code": "action", "meldung": "No files were found with the provided path"}
            return {"status": "ok", "warnung": "keine Dateien"}
        puffer, dateien = io.BytesIO(), []
        with zipfile.ZipFile(puffer, "w", zipfile.ZIP_DEFLATED) as z:
            quelle = [pfad] if os.path.isfile(pfad) else sorted(os.path.join(d, f) for d, _, fs in os.walk(pfad) for f in fs)
            for f in quelle:
                rel = os.path.basename(f) if os.path.isfile(pfad) else os.path.relpath(f, pfad)
                z.write(f, rel)
                dateien.append(rel)
        inhalt = puffer.getvalue()
        self.uploads.append({"name": mit.get("name", "artifact"), "digest": hashlib.sha256(inhalt).hexdigest(),
                             "dateien": dateien, "groesse": len(inhalt), "aufbewahrung": mit.get("retention-days"),
                             "inhalt": inhalt})
        nummer = str(len(self.uploads))
        return {"status": "ok", "ausgaben": {"artifact-id": nummer, "artifact-digest": self.uploads[-1]["digest"],
                                             "artifact-url": "%s/%s/actions/runs/4711/artifacts/%s" % (SERVER, REPO_NAME, nummer)}}

    def protokoll(self, pfad):
        if not os.path.exists(pfad):
            return []
        with open(pfad, encoding="utf-8") as fh:
            return [json.loads(z) for z in fh if z.strip()]


# ---------------------------------------------------------------- Ausführung und Bewertung

def lies_json(pfad):
    with open(pfad, encoding="utf-8") as fh:
        return json.load(fh)


def lade_workflow():
    with open(WORKFLOW, encoding="utf-8") as fh:
        return workflow_check.parse_yaml(fh.read())


def fuehre_aus(szenario, basis, workflow=None):
    workflow = workflow or lade_workflow()
    lauf = Lauf(szenario, basis)
    vor = lauf.job("vorpruefung", workflow["jobs"]["vorpruefung"])
    if vor["status"] == "ok":   # needs: [tests, vorpruefung]; tests = diese Test-Suite selbst; Freigabe angenommen
        lauf.zwischen_den_jobs()
        lauf.job("signieren", workflow["jobs"]["signieren"])
    return lauf


def fuehre_parallel(szenarien, wurzel, workflow=None):
    """Szenarien sind voneinander unabhängig (eigene Ordner, eigene Prozesse) und laufen gleichzeitig."""
    workflow = workflow or lade_workflow()
    with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 2)) as pool:
        return list(pool.map(lambda s: fuehre_aus(s, os.path.join(wurzel, s.name), workflow), szenarien))


def ergebnis(lauf):
    for name in ("vorpruefung", "signieren"):
        job = lauf.jobs.get(name)
        if job and job["status"] != "ok":
            fehler = next(s for s in job["schritte"] if s.get("status") == "fehlgeschlagen")
            return (name, fehler["id"], fehler.get("code"))
    return None


def bewerte(lauf):
    """Abweichungen des Laufs vom erwarteten Ergebnis (leere Liste = Szenario bestanden)."""
    s, ab = lauf.s, []
    erg = ergebnis(lauf)
    if erg != s.erwartet:
        ab.append("Ergebnis %s, erwartet %s" % (erg or "Erfolg", s.erwartet or "Erfolg"))
    signiert = [e for e in lauf.protokoll(lauf.protokoll_signtool) if e["befehl"] == "sign"]
    geprueft = [e for e in lauf.protokoll(lauf.protokoll_signtool) if e["befehl"] == "verify"]
    vor_signatur = s.erwartet is not None and (s.erwartet[0] == "vorpruefung" or s.erwartet[1] in SCHRITTE_VOR_SIGNATUR)
    if vor_signatur and signiert:
        ab.append("Signierwerkzeug lief trotz Abbruch vor der Signatur")
    if not vor_signatur and len(signiert) != 1:
        ab.append("Signierwerkzeug lief %d-mal statt einmal" % len(signiert))
    if s.erwartet and s.erwartet[0] == "vorpruefung" and "signieren" in lauf.jobs:
        ab.append("Signier-Job lief trotz fehlgeschlagener Vorprüfung")
    erwartete_uploads = 1 if s.erwartet is None else 0
    if len(lauf.uploads) != erwartete_uploads:
        ab.append("%d GitHub-Artefakt(e) hochgeladen, erwartet %d" % (len(lauf.uploads), erwartete_uploads))
    for u in lauf.uploads:
        if any(d.lower().endswith(".exe") for d in u["dateien"]) or b"MZ" == u["inhalt"][:2]:
            ab.append("Installer als GitHub-Artefakt %s" % u["name"])
    anfragen = lauf.ablage_workflow()
    puts = [p for p in anfragen if p["methode"] != "GET"]
    erwartete_puts = 1 if s.erwartet is None or s.erwartet[1] in ("hochladen", "ablage_pruefen") else 0
    if len(puts) != erwartete_puts or any(p["methode"] != "PUT" or not p["pfad"].endswith("/signed") for p in puts):
        ab.append("Schreibende Ablage-Anfragen %s, erwartet %d× PUT signed" % ([(p["methode"], p["pfad"]) for p in puts],
                                                                              erwartete_puts))
    token_fall = s.erwartet is not None and s.erwartet[2] in TOKEN_CODES
    if not token_fall and any(p["auth"] not in ("ok", "-") for p in anfragen):
        ab.append("Ablage-Anfrage ohne gültiges Token")
    if s.erwartet and s.erwartet[2] in ("storage_token_fehlt", "repo_unbekannt") and anfragen:
        ab.append("Ablage-Anfrage trotz Abbruch vor dem Token")
    for job in lauf.jobs.values():
        nach_fehler = False
        for schritt in job["schritte"]:
            if nach_fehler and schritt["status"] not in ("uebersprungen",) and schritt["id"] != "abmelden":
                ab.append("Schritt %s lief nach einem Fehler" % schritt["id"])
            nach_fehler = nach_fehler or schritt["status"] == "fehlgeschlagen"
    if s.erwartet is None and erg is None:
        ab += _bewerte_erfolg(lauf, signiert, geprueft)
    return ab


ERFOLG_ANFRAGEN = ([("GET", "manifest"), ("GET", "quality"), ("GET", "manifest"), ("GET", "unsigned")] * 2
                   + [("PUT", "signed"), ("GET", "manifest"), ("GET", "signed")])


def _bewerte_erfolg(lauf, signiert, geprueft):
    ab = []
    job = lauf.jobs["signieren"]
    datei = job["ausgaben"]["vorpruefen"].get("datei", "")
    erwartet = ["sign", "/v", "/debug", "/fd", "SHA256", "/tr", "http://timestamp.acs.microsoft.com", "/td", "SHA256",
                "/dlib", lauf.dlib, "/dmdf", os.path.join(lauf.dlib_ordner, "metadata.json"), "/d", sig.SIGNATUR_BESCHREIBUNG, datei]
    if not signiert or signiert[0]["argv"] != erwartet:
        ab.append("signtool-sign-Argumente weichen ab: %s" % (signiert[0]["argv"] if signiert else None))
    if " " not in datei or " " not in lauf.dlib or " " not in lauf.signtool:
        ab.append("Pfade ohne Leerzeichen – Prüfung wirkungslos")
    soll_meta = {"Endpoint": VARIABLEN["ARTIFACT_SIGNING_ENDPOINT"], "CodeSigningAccountName": VARIABLEN["ARTIFACT_SIGNING_ACCOUNT"],
                 "CertificateProfileName": VARIABLEN["ARTIFACT_SIGNING_PROFILE"],
                 "ExcludeCredentials": [n for _k, _s, n in AUSSCHLUSS if n != "AzureCliCredential"]}
    if not signiert or signiert[0]["metadaten"] != soll_meta:
        ab.append("metadata.json weicht ab")
    if [e["argv"] for e in geprueft] != [list(sig.SIGNTOOL_VERIFY) + [datei]]:
        ab.append("signtool-verify-Aufruf weicht ab: %s" % [e["argv"] for e in geprueft])
    anfragen = [(p["methode"], p["pfad"].rsplit("/", 1)[-1]) for p in lauf.ablage_workflow()]
    if anfragen != ERFOLG_ANFRAGEN or any(p["status"] not in (200, 201) for p in lauf.ablage_workflow()):
        ab.append("Ablage-Anfragen weichen ab: %s" % anfragen)
    ordner = job["ausgaben"]["nachpruefen"].get("nachweis_ordner", "")
    try:
        release, nachweis, bericht = (lies_json(os.path.join(ordner, n)) for n in sig.NACHWEIS_DATEIEN)
    except (OSError, ValueError):
        return ab + ["Nachweisdateien fehlen"]
    with open(datei, "rb") as fh:
        signierte_bytes = fh.read()
    sha_s = hashlib.sha256(signierte_bytes).hexdigest()
    if bericht["sha256_unsigniert"] != lauf.sha256 or bericht["sha256_signiert"] != sha_s or sha_s == lauf.sha256:
        ab.append("Hashes im Bericht stimmen nicht")
    if release["artefakte"][0]["sha256"] != sha_s or release["build_id"] != BUILD_ID or release["git_sha"] != GIT_SHA:
        ab.append("Release-Metadaten stimmen nicht")
    if nachweis["status"] != "ungueltig" or "TROCKENLAUF" not in nachweis["werkzeug"] or not bericht["trockenlauf"]:
        ab.append("Trockenlauf-Nachweis muss ungueltig und gekennzeichnet sein")
    if not all(bericht["pruefungen"].values()) or bericht["auffuellbytes"] != (-len(lauf.installer)) % 8:
        ab.append("Nachprüfung unvollständig")
    ablage = bericht.get("ablage") or {}
    if {k: ablage.get(k) for k in ("build_id", "kind", "dateiname", "sha256", "groesse")} != {
            "build_id": BUILD_ID, "kind": "signed", "dateiname": sig.asset_name(BUILD_ID), "sha256": sha_s,
            "groesse": len(signierte_bytes)} or not ablage.get("uploaded_at"):
        ab.append("Ablage-Prüfung fehlt im Bericht")
    if bericht.get("qualitaet") != {"build_id": BUILD_ID, "bestanden": True, "remote_e2e_fps": QUALITAET["remote_e2e_fps"],
                                    "sha256": hashlib.sha256(lauf.quality).hexdigest()}:
        ab.append("Qualitätsnachweis fehlt im Bericht")
    if lauf.ablage.inhalt(BUILD_ID, "signed") != signierte_bytes or lauf.ablage.inhalt(BUILD_ID, "unsigned") != lauf.installer:
        ab.append("Ablage enthält nicht genau den geprüften signierten bzw. unveränderten unsignierten Installer")
    if len(lauf.uploads) != 1 or lauf.uploads[0]["name"] != "signatur-nachweis-" + BUILD_ID \
            or sorted(lauf.uploads[0]["dateien"]) != sorted(sig.NACHWEIS_DATEIEN) or lauf.uploads[0]["aufbewahrung"] != "30":
        ab.append("Nachweis-Artefakt falsch oder unvollständig")
    for name in sig.NACHWEIS_DATEIEN:
        with open(os.path.join(ordner, name), encoding="utf-8") as fh:
            text = fh.read()
            if lauf.basis in text or ABLAGE_TOKEN in text:
                ab.append("Lokaler Pfad oder Token in %s" % name)
    return ab


def _sha256_datei(pfad):
    with open(pfad, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _ohne_pfad(obj, basis):
    text = json.dumps(obj, ensure_ascii=False)
    for variante in (basis, json.dumps(basis)[1:-1]):
        text = text.replace(variante, "<trockenlauf>")
    return json.loads(text)


def bericht_eintrag(lauf, abweichungen):
    eintrag = {"name": lauf.s.name, "beschreibung": lauf.s.beschreibung,
               "erwartet": list(lauf.s.erwartet) if lauf.s.erwartet else "erfolg",
               "ergebnis": list(ergebnis(lauf)) if ergebnis(lauf) else "erfolg", "ok": not abweichungen,
               "abweichungen": abweichungen,
               "schritte": {j: [(s["id"], s["status"], s.get("code")) for s in d["schritte"]] for j, d in lauf.jobs.items()},
               "signtool_aufrufe": [e["befehl"] for e in lauf.protokoll(lauf.protokoll_signtool)],
               "ablage_anfragen": [(p["methode"], p["pfad"], p["status"]) for p in lauf.ablage_workflow()],
               "github_artefakte": [{k: u[k] for k in ("name", "digest", "dateien")} for u in lauf.uploads]}
    if lauf.s.erwartet is None and lauf.aktion_signieren:
        nach = lauf.jobs["signieren"]["ausgaben"]
        with open(os.path.join(nach["nachpruefen"]["nachweis_ordner"], "signatur-bericht.json"), encoding="utf-8") as fh:
            b = json.load(fh)
        eintrag["beweise"] = {"start_process_zeile": lauf.aktion_signieren["kommandozeile"],
                              "signtool_sign_argv": lauf.aktion_signieren["argv"], "metadata_json": lauf.aktion_signieren["metadaten"],
                              "signtool_verify_argv": list(sig.SIGNTOOL_VERIFY) + [nach["vorpruefen"]["datei"]],
                              "sha256_unsigniert": b["sha256_unsigniert"], "sha256_signiert": b["sha256_signiert"],
                              "authenticode_sha256": b["authenticode_sha256"], "auffuellbytes": b["auffuellbytes"],
                              "ablage": b["ablage"], "qualitaet": b["qualitaet"], "nachweis_status": "ungueltig (Trockenlauf)"}
    return _ohne_pfad(eintrag, lauf.basis)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bericht", help="Bericht als JSON schreiben")
    ap.add_argument("--szenario", action="append", default=[], help="nur diese Szenarien")
    ap.add_argument("--behalten", action="store_true", help="Arbeitsordner nicht löschen")
    args = ap.parse_args(argv)
    auswahl = [s for s in SZENARIEN if not args.szenario or s.name in args.szenario]
    if args.szenario and len(auswahl) != len(set(args.szenario)):
        ap.error("unbekanntes Szenario")
    with open(WORKFLOW, encoding="utf-8") as fh:
        workflow_text = fh.read()
    befunde = workflow_check.pruefe_workflow(workflow_text)
    workflow = workflow_check.parse_yaml(workflow_text)
    wurzel = tempfile.mkdtemp(prefix="Insight Signing Trockenlauf ")
    eintraege = []
    try:
        laeufe = fuehre_parallel(auswahl, wurzel, workflow)
        for s, lauf in zip(auswahl, laeufe):
            ab = bewerte(lauf)
            eintraege.append(bericht_eintrag(lauf, ab))
            erg = ergebnis(lauf)
            print("%-4s %-30s %s" % ("OK" if not ab else "ROT", s.name, "Erfolg" if erg is None else "Abbruch %s/%s [%s]" % erg))
            for a in ab:
                print("       - " + a)
    finally:
        if not args.behalten:
            shutil.rmtree(wurzel, ignore_errors=True)
    for b in befunde:
        print("BEFUND [%s] %s" % (b["code"], b["meldung"]))
    gesamt = not befunde and all(e["ok"] for e in eintraege)
    bericht = {"format": "insight-signing-trockenlauf/2", "erstellt_am": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
               "workflow_sha256": hashlib.sha256(workflow_text.encode("utf-8")).hexdigest(),
               "helfer_sha256": _sha256_datei(HELFER),
               "statische_pruefung": "ohne Befund" if not befunde else befunde, "szenarien": eintraege,
               "gesamt": "bestanden" if gesamt else "fehlgeschlagen"}
    if args.bericht:
        with open(args.bericht, "w", encoding="utf-8") as fh:
            json.dump(bericht, fh, ensure_ascii=False, indent=1)
    print("Trockenlauf: %d/%d Szenarien wie erwartet, statische Prüfung %s – %s"
          % (sum(e["ok"] for e in eintraege), len(eintraege), "ohne Befund" if not befunde else "%d Befund(e)" % len(befunde),
             bericht["gesamt"]))
    return 0 if gesamt else 1


if __name__ == "__main__":
    sys.exit(main())
