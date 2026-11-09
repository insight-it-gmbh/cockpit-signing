#!/usr/bin/env python3
"""Tests für den Signaturpfad des Fernwartungs-Installers (öffentliches Repository, private Artefaktablage).

Rein lokal und synthetisch: kein Azure, kein GitHub, kein Netz (Socket-Verbindungen sind gesperrt), keine echten
Installer oder Zugangsdaten. HTTP läuft ausschließlich über injizierte Fake-Transporte.
- PE/NSIS/Versionsressource/Authenticode an synthetischen Installern (PE32 und PE32+)
- strenge Auswertung von `signtool verify /pa /tw /v` (Format echter Artifact-Signing-Ausgaben)
- Eingaben, Repository-Bindung (öffentlich erlaubt, full_name), Environment-Schutz
- Ablage: Client (Kopfzeilen, Statuscodes, Token nie in Meldungen), Manifest/Quality-Prüfung, produktiver Transport
  ohne Netz (URL-Grenzen, keine Weiterleitungen), Vertrag der Fake-Ablage
- statische Workflow-Prüfung (YAML-Teilmenge, Schema, Pins, Secret-Ort, kein Release/Installer-Artefakt) inkl. Mutationen
- vollständiger Trockenlauf aller Szenarien mit Fake-signtool/-gh/-Ablage
- vorbereiten.py: gedruckte curl-/gh-Befehle laufen unter bash gegen curl-/gh-Doubles
- Runbook und README (Pflichtinhalte), Secret- und Host-Scan über das ganze Repository

Aufruf: python3 tools/test_artifact_signing.py   (pytest-kompatibel)
"""
import hashlib
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SIGNING = os.path.join(HERE, "signing")
sys.path.insert(0, HERE)
sys.path.insert(0, SIGNING)

import artifact_signing as sig  # noqa: E402
import fake_signtool  # noqa: E402
import fake_storage  # noqa: E402
import trockenlauf as tl  # noqa: E402
import vorbereiten as vb  # noqa: E402
import workflow_check as wc  # noqa: E402

WORKFLOW = wc.WORKFLOW
DOKU = os.path.join(REPO, "docs", "release-signing.md")
README = os.path.join(REPO, "README.md")
BID = tl.BUILD_ID
NULL_SHA1 = "0" * 40
TOKEN_TEST = tl.ABLAGE_TOKEN
BASIS = sig.STORAGE_BASIS

# ---------------------------------------------------------------- kein echtes Netz in diesem Prozess
_NETZ_PATCHES = []


def _netz_verboten(*_a, **_k):
    raise AssertionError("Netzzugriff in Tests verboten")


def setUpModule():
    for ziel in ("socket.socket.connect", "socket.socket.connect_ex", "socket.create_connection", "socket.getaddrinfo"):
        p = mock.patch(ziel, _netz_verboten)
        p.start()
        _NETZ_PATCHES.append(p)


def tearDownModule():
    while _NETZ_PATCHES:
        _NETZ_PATCHES.pop().stop()


def echte_ausgabe(authenticode, inhaber="Beispiel Herausgeber GmbH", aussteller="Microsoft ID Verified CS AOC CA 04",
                  zeitstempel=True, fehler=0, warnungen=0):
    """signtool verify /pa /v im Format einer echten Artifact-Signing-Signatur (neutrale Namen)."""
    zeilen = ["Verifying: D:\\a\\_temp\\insight-signing\\signiert\\%s" % sig.asset_name(BID), "",
              "Signature Index: 0 (Primary Signature)", "Hash of file (sha256): %s" % authenticode.upper(), "",
              "Signing Certificate Chain:",
              "    Issued to: Microsoft Identity Verification Root Certificate Authority 2020",
              "    Issued by: Microsoft Identity Verification Root Certificate Authority 2020",
              "    Expires:   Sun Apr 16 20:44:40 2045", "    SHA1 hash: " + NULL_SHA1,
              "        Issued to: Microsoft ID Verified Code Signing PCA 2021",
              "        Issued by: Microsoft Identity Verification Root Certificate Authority 2020",
              "        Expires:   Tue Apr 01 22:15:20 2036", "        SHA1 hash: " + NULL_SHA1,
              "            Issued to: " + aussteller,
              "            Issued by: Microsoft ID Verified Code Signing PCA 2021",
              "            Expires:   Wed Mar 26 20:11:29 2031", "            SHA1 hash: " + NULL_SHA1,
              "                Issued to: " + inhaber, "                Issued by: " + aussteller,
              "                Expires:   Thu Nov 12 07:15:13 2026", "                SHA1 hash: " + NULL_SHA1]
    if zeitstempel:
        zeilen += ["The signature is timestamped: Mon Nov 09 12:00:00 2026", "Timestamp Verified by:",
                   "    Issued to: Microsoft Identity Verification Root Certificate Authority 2020",
                   "    Issued by: Microsoft Identity Verification Root Certificate Authority 2020",
                   "        Issued to: Microsoft Public RSA Timestamping CA 2020",
                   "        Issued by: Microsoft Identity Verification Root Certificate Authority 2020",
                   "            Issued to: Microsoft Public RSA Time Stamping Authority",
                   "            Issued by: Microsoft Public RSA Timestamping CA 2020"]
    else:
        zeilen.append("File is not timestamped.")
    zeilen += ["Successfully verified: D:\\a\\_temp\\insight-signing\\signiert\\%s" % sig.asset_name(BID),
               "Number of files successfully Verified: 1", "Number of warnings: %d" % warnungen, "Number of errors: %d" % fehler]
    return "\n".join(zeilen)


def code_von(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except sig.SigningError as exc:
        return exc.code
    return None


def meldung_von(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except sig.SigningError as exc:
        return exc.meldung
    return ""


def gueltige_eingaben(**aenderung):
    env = {"SIGN_BUILD_ID": BID, "SIGN_SHA256": "a" * 64, "SIGN_QUALITY_SHA256": "c" * 64, "SIGN_VERSION": "2026.11.1",
           "SIGN_KANAL": "pilot", "SIGN_VORGAENGER_ID": "", "SIGN_ERSTAUSROLLUNG": "true"}
    env.update(aenderung)
    return env


class PeUndVersionsressource(unittest.TestCase):
    def test_synthetischer_installer_pe32_und_pe32plus(self):
        for pe32plus, maschine in ((False, "x86"), (True, "x64")):
            with self.subTest(pe32plus=pe32plus):
                data = tl.baue_installer(pe32plus=pe32plus)
                lay = sig.pe_layout(data)
                self.assertEqual(lay["maschine"], maschine)
                self.assertEqual((lay["sec_va"], lay["sec_size"]), (0, 0))
                werte = sig.version_strings(data, lay)
                self.assertEqual(werte["ProductName"], sig.PRODUKT)
                self.assertEqual(werte["CompanyName"], sig.HERSTELLER)
                self.assertEqual((werte["FileVersion"], werte["BuildId"]), (BID, BID))
                self.assertTrue(sig.nsis_kennung(data, lay))
                self.assertEqual(sig.zertifikatstabelle(data, lay), [])
                p, s = lay["pruefsumme_off"], lay["secdir_off"]
                von_hand = hashlib.sha256(data[:p] + data[p + 4:s] + data[s + 8:]).hexdigest()
                self.assertEqual(sig.authenticode_sha256(data, lay), von_hand)
                self.assertEqual(sig.pruefe_installer(data, BID)[1]["BuildId"], BID)

    def test_kaputte_und_fremde_dateien(self):
        gut = tl.baue_installer()
        self.assertEqual(code_von(sig.pe_layout, b"kein Programm" * 10), "kein_pe")
        self.assertEqual(code_von(sig.pe_layout, gut[:0x150]), "pe_defekt")
        arm = bytearray(gut)
        struct.pack_into("<H", arm, 0x84, 0x01C0)
        self.assertEqual(code_von(sig.pe_layout, bytes(arm)), "pe_architektur")
        ohne_res = bytearray(gut)
        lay = sig.pe_layout(gut)
        struct.pack_into("<II", ohne_res, lay["secdir_off"] - 16, 0, 0)
        self.assertEqual(code_von(sig.version_strings, bytes(ohne_res)), "versionsinfo_fehlt")
        self.assertEqual(code_von(sig.pruefe_installer, tl.baue_installer(nsis=False), BID), "kein_nsis")
        self.assertEqual(code_von(sig.pruefe_installer, tl.baue_installer(produkt="Anderes"), BID), "hersteller_abweichung")
        self.assertEqual(code_von(sig.pruefe_installer, gut, "20261109-120001"), "build_id_abweichung")

    def test_signatur_anhaengen_inhaltsvergleich_und_manipulation(self):
        unsigniert = tl.baue_installer()
        signiert = fake_signtool.signiere_bytes(unsigniert, {"kette": [], "zeitstempel": None})
        lay_u, lay_s = sig.pe_layout(unsigniert), sig.pe_layout(signiert)
        tabelle = sig.zertifikatstabelle(signiert, lay_s)
        self.assertEqual([(t["revision"], t["typ"]) for t in tabelle], [(sig.WIN_CERT_REVISION, sig.WIN_CERT_PKCS)])
        auffuellung = sig.inhalt_vergleich(unsigniert, signiert, lay_u, lay_s)
        self.assertEqual(auffuellung, (-len(unsigniert)) % 8)
        self.assertGreater(auffuellung, 0)   # Fall „Datei nicht 8-Byte-ausgerichtet“ abgedeckt
        aufgefuellt = unsigniert + b"\0" * auffuellung
        self.assertEqual(sig.authenticode_sha256(signiert, lay_s), sig.authenticode_sha256(aufgefuellt))
        for stelle in (0x200, len(unsigniert) - 1):          # Kopf und Overlay
            m = bytearray(signiert)
            m[stelle] ^= 0x01
            self.assertEqual(code_von(sig.inhalt_vergleich, unsigniert, bytes(m), lay_u, sig.pe_layout(bytes(m))),
                             "inhalt_geaendert")
        ungerade = bytearray(signiert)
        struct.pack_into("<I", ungerade, lay_s["secdir_off"], lay_s["sec_va"] + 4)
        self.assertEqual(code_von(sig.zertifikatstabelle, bytes(ungerade), sig.pe_layout(bytes(ungerade))),
                         "zertifikatstabelle_lage")


class SigntoolAuswertung(unittest.TestCase):
    AUTH = "ab" * 32

    def bewerte(self, text, exitcode=0, herausgeber="Beispiel Herausgeber GmbH"):
        return sig.bewerte_signtool(sig.parse_signtool(text), exitcode, herausgeber, self.AUTH)

    def test_echtes_format_wird_akzeptiert(self):
        erg = sig.parse_signtool(echte_ausgabe(self.AUTH))
        self.assertEqual(len(erg["kette"]), 4)
        self.assertEqual(len(erg["zeitstempel_kette"]), 3)
        self.assertFalse(erg["fake"])
        blatt = self.bewerte(echte_ausgabe(self.AUTH))
        self.assertEqual((blatt["ausgestellt_fuer"], blatt["ausgestellt_von"]),
                         ("Beispiel Herausgeber GmbH", "Microsoft ID Verified CS AOC CA 04"))
        for ca in ("Microsoft ID Verified CS EOC CA 01", "Microsoft ID Verified CS EOC CA 02",
                   "Microsoft ID Verified CS AOC CA 03", "Microsoft ID Verified CS EOC CA 04"):
            self.assertEqual(self.bewerte(echte_ausgabe(self.AUTH, aussteller=ca))["ausgestellt_von"], ca)

    def test_jede_abweichung_ist_ein_abbruch(self):
        faelle = {
            "signtool_verify": (echte_ausgabe(self.AUTH), 1),
            "nicht_verifiziert": (echte_ausgabe(self.AUTH, warnungen=1), 0),
            "zeitstempel_fehlt": (echte_ausgabe(self.AUTH, zeitstempel=False), 0),
            "aussteller_abweichung": (echte_ausgabe(self.AUTH, aussteller="Beispiel Code Signing CA"), 0),
            "herausgeber_abweichung": (echte_ausgabe(self.AUTH, inhaber="Fremdfirma GmbH"), 0),
            "authenticode_abweichung": (echte_ausgabe("cd" * 32), 0),
            "signatur_format": (echte_ausgabe(self.AUTH).replace("Signature Index: 0 (Primary Signature)",
                                                               "Signature Index: 0 (Primary Signature)\nSignature Index: 1"), 0),
            "signtool_ausgabe": ("Successfully verified: x\nNumber of files successfully Verified: 1\n"
                                 "Number of warnings: 0\nNumber of errors: 0\nSignature Index: 0", 0),
        }
        for code, (text, exitcode) in faelle.items():
            with self.subTest(code=code):
                self.assertEqual(code_von(self.bewerte, text, exitcode), code)

    def test_selbstsigniert_nie_erfolg(self):
        selbst = "\n".join(["Signature Index: 0 (Primary Signature)", "Hash of file (sha256): " + self.AUTH,
                            "Signing Certificate Chain:", "    Issued to: Beispiel Herausgeber GmbH",
                            "    Issued by: Beispiel Herausgeber GmbH", "The signature is timestamped: Mon Nov 09 2026",
                            "Timestamp Verified by:", "    Issued to: X", "    Issued by: X", "Successfully verified: x",
                            "Number of files successfully Verified: 1", "Number of warnings: 0", "Number of errors: 0"])
        self.assertEqual(code_von(self.bewerte, selbst), "selbstsigniert")
        self.assertEqual(code_von(self.bewerte, selbst.replace("Beispiel Herausgeber GmbH", sig.AUSSTELLER_PRAEFIX + "X"),
                                  0, sig.AUSSTELLER_PRAEFIX + "X"), "selbstsigniert")

    def test_fake_kennung_wird_erkannt(self):
        self.assertTrue(sig.parse_signtool(fake_signtool.KENNUNG + "\n" + echte_ausgabe(self.AUTH))["fake"])
        self.assertIn(sig.FAKE_KENNUNG, fake_signtool.KENNUNG)


class Eingaben(unittest.TestCase):
    def test_gueltig_und_abgeleitete_namen_ohne_kundenbezug(self):
        e = sig.lese_eingaben(gueltige_eingaben())
        self.assertEqual(e["asset"], "insight-fernwartung-%s.exe" % BID)
        self.assertNotIn("release_tag", e)                       # kein Pre-Release mehr
        self.assertTrue(sig.ARTEFAKT_RE.match(e["asset"]))
        self.assertEqual(sig.ablage_dateiname(BID, "quality"), "quality.json")
        self.assertEqual(sig.ablage_dateiname(BID, "signed"), e["asset"])
        e = sig.lese_eingaben(gueltige_eingaben(SIGN_ERSTAUSROLLUNG="false", SIGN_VORGAENGER_ID="R-0123456789ab",
                                                SIGN_SHA256="A" * 64, SIGN_QUALITY_SHA256="C" * 64))
        self.assertEqual((e["vorgaenger_id"], e["erstausrollung"], e["sha256"], e["quality_sha256"]),
                         ("R-0123456789ab", False, "a" * 64, "c" * 64))

    def test_ungueltige_eingaben(self):
        faelle = {
            "eingabe_build_id": [{"SIGN_BUILD_ID": "2026-11-09"}, {"SIGN_BUILD_ID": "20261340-120000"},
                                 {"SIGN_BUILD_ID": "kunde-20261109-120000"}, {"SIGN_BUILD_ID": "../20261109-120000"}],
            "eingabe_sha256": [{"SIGN_SHA256": "a" * 63}, {"SIGN_SHA256": "g" * 64}],
            "eingabe_quality_sha256": [{"SIGN_QUALITY_SHA256": ""}, {"SIGN_QUALITY_SHA256": "c" * 63},
                                       {"SIGN_QUALITY_SHA256": "z" * 64}],
            "eingabe_version": [{"SIGN_VERSION": ""}, {"SIGN_VERSION": "1.0 beta"}],
            "eingabe_kanal": [{"SIGN_KANAL": "live"}],
            "eingabe_vorgaenger": [{"SIGN_VORGAENGER_ID": "R 1", "SIGN_ERSTAUSROLLUNG": "false"}],
            "eingabe_rollback": [{"SIGN_ERSTAUSROLLUNG": "false"}, {"SIGN_VORGAENGER_ID": "R-0123456789ab"},
                                 {"SIGN_ERSTAUSROLLUNG": "ja"}],
            "eingabe_ref": [{"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/feature"},
                            {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/tags/cockpit-v1"}],
            "override_verboten": [{"RUNNER_ENVIRONMENT": "github-hosted", k: "x"} for k in sig.UEBERSCHREIBUNGEN]
            + [{"GITHUB_ACTIONS": "true", "GITHUB_REF": sig.REF_ERLAUBT, k: "x"} for k in sig.UEBERSCHREIBUNGEN]
            + [{"RUNNER_ENVIRONMENT": "self-hosted", k: "x"} for k in sig.UEBERSCHREIBUNGEN],
        }
        faelle["eingabe_ref"].append({"SIGN_GITHUB_SIMULATION": "1", "GITHUB_REF": "refs/heads/feature"})
        self.assertIn("SIGN_STORAGE_FAKE", sig.UEBERSCHREIBUNGEN)
        for code, varianten in faelle.items():
            for v in varianten:
                with self.subTest(code=code, v=v):
                    self.assertEqual(code_von(sig.lese_eingaben, gueltige_eingaben(**v)), code)
        self.assertIsNotNone(sig.lese_eingaben(gueltige_eingaben(GITHUB_ACTIONS="true", GITHUB_REF=sig.REF_ERLAUBT,
                                                                 RUNNER_ENVIRONMENT="github-hosted")))
        self.assertIsNotNone(sig.lese_eingaben(gueltige_eingaben(SIGN_GH="gh.py", SIGN_SIGNTOOL="signtool.py",
                                                                 SIGN_TROCKENLAUF="1", SIGN_STORAGE_FAKE="/x",
                                                                 SIGN_GITHUB_SIMULATION="1", GITHUB_REF=sig.REF_ERLAUBT)))


def ereignis(**repo):
    """Ereignis-Nutzlast (GITHUB_EVENT_PATH) eines workflow_dispatch mit Repository-Angaben."""
    r = {"full_name": "beispiel/cockpit-signing", "private": False, "visibility": "public"}
    for k, v in repo.items():
        if v is None:
            r.pop(k, None)
        else:
            r[k] = v
    return {"inputs": {}, "ref": sig.REF_ERLAUBT, "repository": r}


class RepositoryBindung(unittest.TestCase):
    """Öffentliches Repository erlaubt (Installer nur in der Ablage); full_name muss GITHUB_REPOSITORY entsprechen."""
    REPO = "beispiel/cockpit-signing"

    def test_oeffentlich_und_privat_bestehen(self):
        self.assertEqual(sig.pruefe_repo(ereignis(), self.REPO), "public")
        self.assertEqual(sig.pruefe_repo(ereignis(visibility=None), self.REPO), "public")
        self.assertEqual(sig.pruefe_repo(ereignis(private=True, visibility="private"), self.REPO), "private")
        self.assertEqual(sig.pruefe_repo(ereignis(private=True, visibility=None), self.REPO), "private")
        self.assertEqual(sig.pruefe_repo(ereignis(private=True, visibility="internal"), self.REPO), "internal")
        self.assertEqual(sig.pruefe_repo(ereignis(full_name="Beispiel/Cockpit-Signing"), self.REPO), "public")

    def test_unbekannt_fremd_oder_widerspruechlich_bricht_ab(self):
        varianten = [ereignis(private=None), ereignis(private="false"), ereignis(private=0),
                     ereignis(full_name=None), ereignis(full_name="fremd/cockpit-signing"),
                     ereignis(full_name="beispiel/cockpit-signing/x"), ereignis(full_name=["beispiel/cockpit-signing"]),
                     ereignis(private=False, visibility="private"), ereignis(private=True, visibility="public"),
                     ereignis(visibility="geheim"), {"inputs": {}}, None, []]
        for e in varianten:
            with self.subTest(e=e):
                self.assertEqual(code_von(sig.pruefe_repo, e, self.REPO), "repo_unbekannt")
        self.assertEqual(code_von(sig.pruefe_repo, ereignis(), "kein-repo"), "repo_unbekannt")

    def ausfuehren(self, befehl, ereignis_obj, ablage_ordner):
        tmp = tempfile.mkdtemp(prefix="Insight Repo ")
        try:
            pfad = os.path.join(tmp, "ereignis.json")
            if ereignis_obj is not None:
                with open(pfad, "w", encoding="utf-8") as fh:
                    json.dump(ereignis_obj, fh)
            protokoll = os.path.join(tmp, "gh.jsonl")
            umg = os.path.join(tmp, "umg.json")
            with open(umg, "w", encoding="utf-8") as fh:
                json.dump({"name": "release-signing"}, fh)
            env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT") if k in os.environ}
            env.update(gueltige_eingaben(), RUNNER_TEMP=tmp, GITHUB_REPOSITORY=self.REPO, GITHUB_EVENT_PATH=pfad,
                       SIGN_GH=os.path.join(SIGNING, "fake_gh.py"), FAKE_GH_PROTOKOLL=protokoll, FAKE_GH_UMGEBUNG=umg,
                       FAKE_GH_ZWEIGE=umg, SIGN_STORAGE_FAKE=ablage_ordner, PYTHONIOENCODING="utf-8",
                       **{"SIGNING_STORAGE_TOKEN": TOKEN_TEST})
            p = subprocess.run([sys.executable, os.path.join(SIGNING, "artifact_signing.py"), befehl], env=env,
                               capture_output=True, text=True, timeout=60)
            return p, tl.Lauf.protokoll(None, protokoll)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_abbruch_vor_jedem_gh_und_ablage_aufruf(self):
        tmp = tempfile.mkdtemp(prefix="Insight Ablage ")
        try:
            ablage = fake_storage.FakeAblage.einrichten(tmp, TOKEN_TEST)
            for befehl in ("umgebung", "qualitaet", "laden"):
                for e in (ereignis(private=None), ereignis(full_name="fremd/x"), None):
                    with self.subTest(befehl=befehl, e=e):
                        p, aufrufe = self.ausfuehren(befehl, e, tmp)
                        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                        self.assertIn("FEHLER [repo_unbekannt]", p.stderr)
                        self.assertEqual(aufrufe, [])
                        self.assertEqual(ablage.protokoll(), [])          # Token nie benutzt
            # öffentliches Repository kommt durch die Repository-Prüfung (bricht erst an fehlenden Reviewern ab)
            p, aufrufe = self.ausfuehren("umgebung", ereignis(), tmp)
            self.assertIn("FEHLER [umgebung_ungeschuetzt]", p.stderr)
            self.assertEqual(len(aufrufe), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class UmgebungsSchutz(unittest.TestCase):
    UMG = {"name": "release-signing", "can_admins_bypass": False,
           "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
           "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True,
                                 "reviewers": [{"type": "User"}, {"type": "Team"}]}, {"type": "branch_policy"}]}
    ZW = {"total_count": 1, "branch_policies": [{"id": 1, "name": "main", "type": "branch"}]}

    def test_geschuetzt(self):
        self.assertEqual(sig.pruefe_umgebung(self.UMG, self.ZW), (2, []))
        ohne_vier_augen = json.loads(json.dumps(self.UMG))
        ohne_vier_augen["protection_rules"][0]["prevent_self_review"] = False
        self.assertEqual(len(sig.pruefe_umgebung(ohne_vier_augen, self.ZW)[1]), 1)
        ohne_feld = dict(self.UMG)
        del ohne_feld["can_admins_bypass"]
        anzahl, hinweise = sig.pruefe_umgebung(ohne_feld, self.ZW)
        self.assertEqual(anzahl, 2)
        self.assertTrue(any("can_admins_bypass" in h and "Portal" in h for h in hinweise), hinweise)

    def test_ungeschuetzt_bricht_ab(self):
        faelle = {
            "umgebung_fehlt": [(dict(self.UMG, name="production"), self.ZW), (None, self.ZW)],
            "umgebung_admin_bypass": [(dict(self.UMG, can_admins_bypass=True), self.ZW),
                                      (dict(self.UMG, can_admins_bypass="true"), self.ZW)],
            "umgebung_ungeschuetzt": [(dict(self.UMG, protection_rules=[]), self.ZW),
                                      (dict(self.UMG, protection_rules=[{"type": "required_reviewers", "reviewers": []}]), self.ZW),
                                      (dict(self.UMG, protection_rules=[{"type": "wait_timer", "wait_timer": 5}]), self.ZW)],
            "umgebung_zweige": [(dict(self.UMG, deployment_branch_policy=None), self.ZW),
                                (dict(self.UMG, deployment_branch_policy={"protected_branches": True, "custom_branch_policies": False}), self.ZW),
                                (self.UMG, {"branch_policies": []}),
                                (self.UMG, {"branch_policies": [{"name": "main"}, {"name": "release/*"}]}),
                                (self.UMG, {"branch_policies": [{"name": "main", "type": "tag"}]})],
        }
        for code, varianten in faelle.items():
            for umg, zw in varianten:
                with self.subTest(code=code, umg=umg, zw=zw):
                    self.assertEqual(code_von(sig.pruefe_umgebung, umg, zw), code)


# ---------------------------------------------------------------- Ablage: Client, Transport, Vertrag

class Aufzeichner:
    """Transport-Double: zeichnet Anfragen auf und liefert vorgegebene Antworten (kein Netz)."""

    def __init__(self, antworten):
        self.antworten, self.anfragen = list(antworten), []

    def __call__(self, methode, url, kopf, body, max_antwort):
        self.anfragen.append({"methode": methode, "url": url, "kopf": dict(kopf), "body": body, "max": max_antwort})
        return self.antworten.pop(0)


def manifest(build_id=BID, **arten):
    return {"build_id": build_id, "artifacts": [
        {"kind": k, "filename": sig.ablage_dateiname(build_id, k), "sha256": v[0], "size": v[1],
         "uploaded_at": "2026-11-09T12:00:00+00:00"} for k, v in arten.items()]}


class AblageClient(unittest.TestCase):
    def test_kopfzeilen_urls_und_token_nur_im_authorization_kopf(self):
        data = tl.baue_installer()
        sha = hashlib.sha256(data).hexdigest()
        t = Aufzeichner([(200, json.dumps(manifest(unsigned=(sha, len(data)))).encode()), (200, data), (201, b"{}")])
        a = sig.Ablage(t, TOKEN_TEST)
        self.assertEqual(sig.pruefe_manifest(a.manifest(BID), BID, "unsigned", sha)["size"], len(data))
        self.assertEqual(a.lade(BID, "unsigned", sig.MAX_GROESSE), data)
        a.lege_ab(BID, "signed", data, sha)
        self.assertEqual([(x["methode"], x["url"]) for x in t.anfragen],
                         [("GET", "%s/%s/manifest" % (BASIS, BID)), ("GET", "%s/%s/unsigned" % (BASIS, BID)),
                          ("PUT", "%s/%s/signed" % (BASIS, BID))])
        for x in t.anfragen:
            self.assertEqual(x["kopf"]["Authorization"], "Bearer " + TOKEN_TEST)
            self.assertNotIn(TOKEN_TEST, x["url"])
        put = t.anfragen[2]
        self.assertEqual((put["kopf"]["X-Artifact-SHA256"], put["kopf"]["Content-Type"], put["body"]),
                         (sha, "application/octet-stream", data))
        self.assertEqual(t.anfragen[1]["max"], sig.MAX_GROESSE)
        self.assertNotIn(TOKEN_TEST, repr(a))
        self.assertEqual(sig.MAX_GROESSE, 200 * 1024 * 1024)
        self.assertEqual(BASIS, "https://cockpit.insight-it.de/api/signing/artifacts")

    def test_statuscodes_werden_zu_fehlercodes_ohne_token_oder_antworttext(self):
        faelle = {400: "storage_anfrage", 401: "storage_token", 404: "storage_fehlt", 409: "storage_konflikt",
                  413: "storage_zu_gross", 422: "storage_abgelehnt", 503: "storage_nicht_konfiguriert", 500: "storage_fehler"}
        for status, code in faelle.items():
            with self.subTest(status=status):
                a = sig.Ablage(Aufzeichner([(status, b"interne Details und " + TOKEN_TEST.encode())]), TOKEN_TEST)
                self.assertEqual(code_von(a.manifest, BID), code)
                text = meldung_von(sig.Ablage(Aufzeichner([(status, TOKEN_TEST.encode())]), TOKEN_TEST).manifest, BID)
                self.assertNotIn(TOKEN_TEST, text)
                self.assertNotIn("interne Details", text)
        a = sig.Ablage(Aufzeichner([(404, b"")]), TOKEN_TEST)
        self.assertEqual(code_von(a.lade, BID, "quality", 10, fehlt_code="quality_fehlt"), "quality_fehlt")
        self.assertEqual(code_von(sig.Ablage(Aufzeichner([(200, b"kein json")]), TOKEN_TEST).manifest, BID), "manifest_ungueltig")

    def test_token_und_eingaben_vor_jeder_anfrage_geprueft(self):
        t = Aufzeichner([])
        for token, code in (("", "storage_token_fehlt"), ("   ", "storage_token_fehlt"), ("kurz", "storage_token_format"),
                            ("mit leerzeichen 0123456789", "storage_token_format"),
                            (TOKEN_TEST + "\n", "storage_token_format"), ("ä" * 20, "storage_token_format")):
            with self.subTest(token=token):
                self.assertEqual(code_von(sig.lies_token, {"SIGNING_STORAGE_TOKEN": token}), code)
                self.assertNotIn(token.strip() or "§", meldung_von(sig.lies_token, {"SIGNING_STORAGE_TOKEN": token}))
        self.assertEqual(code_von(sig.lies_token, {}), "storage_token_fehlt")
        self.assertEqual(sig.lies_token({"SIGNING_STORAGE_TOKEN": TOKEN_TEST}), TOKEN_TEST)
        a = sig.Ablage(t, TOKEN_TEST)
        for bid, teil in (("../etc", "manifest"), (BID + "/..", "unsigned"), (BID, "../signed"), (BID, "liste")):
            self.assertEqual(code_von(a._url, bid, teil), "storage_anfrage")
        self.assertEqual(code_von(a.lege_ab, BID, "signed", b"MZ", "0" * 64), "datei_veraendert")
        self.assertEqual(t.anfragen, [])
        self.assertEqual(code_von(sig.Ablage, t, TOKEN_TEST, "https://andere.example.invalid/api/signing/artifacts"),
                         "storage_url")

    def test_manifest_pruefung(self):
        sha = "b" * 64
        gut = manifest(unsigned=(sha, 1000), quality=("c" * 64, 120))
        self.assertEqual(sig.pruefe_manifest(gut, BID, "unsigned", sha)["filename"], sig.asset_name(BID))
        self.assertEqual(sig.pruefe_manifest(gut, BID, "quality")["filename"], "quality.json")
        doppelt = manifest(unsigned=(sha, 1000))
        doppelt["artifacts"] *= 2
        falscher_name = manifest(unsigned=(sha, 1000))
        falscher_name["artifacts"][0]["filename"] = "kunde-beispiel.exe"
        faelle = {"digest_abweichung": (gut, "unsigned", "d" * 64), "asset_fehlt": (manifest(quality=(sha, 1)), "unsigned", sha),
                  "asset_mehrdeutig": (doppelt, "unsigned", sha), "asset_name": (falscher_name, "unsigned", sha),
                  "asset_groesse": (manifest(unsigned=(sha, 0)), "unsigned", sha),
                  "manifest_ungueltig": (manifest(build_id="20261109-120001", unsigned=(sha, 1)), "unsigned", sha)}
        faelle["asset_groesse_2"] = (manifest(unsigned=(sha, sig.MAX_GROESSE + 1)), "unsigned", sha)
        faelle["asset_groesse_3"] = (manifest(quality=(sha, sig.MAX_QUALITY + 1)), "quality", sha)
        faelle["asset_groesse_4"] = (manifest(unsigned=(sha, True)), "unsigned", sha)
        faelle["manifest_ungueltig_2"] = ({"build_id": BID, "artifacts": "x"}, "unsigned", sha)
        faelle["manifest_ungueltig_3"] = (manifest(unsigned=("x" * 64, 1)), "unsigned", None)
        for code, (m, art, erwartet) in faelle.items():
            with self.subTest(code=code):
                self.assertEqual(code_von(sig.pruefe_manifest, m, BID, art, erwartet), code.rstrip("_234"))
        self.assertEqual(code_von(sig.pruefe_manifest, gut, BID, "signed", None, fehlt_code="upload_fehlt"), "upload_fehlt")

    def test_quality_pruefung(self):
        gut = json.loads(tl.quality_bytes())
        self.assertEqual(sig.pruefe_quality(gut, BID), {"build_id": BID, "bestanden": True, "remote_e2e_fps": 15.2})
        self.assertEqual(sig.pruefe_quality(dict(gut, remote_e2e_fps=14), BID)["remote_e2e_fps"], 14.0)
        for kaputt in (dict(gut, bestanden=False), dict(gut, bestanden="true"), dict(gut, bestanden=1),
                       {k: v for k, v in gut.items() if k != "bestanden"}, dict(gut, build_id="20261109-120001"),
                       {k: v for k, v in gut.items() if k != "remote_e2e_fps"}, dict(gut, remote_e2e_fps="15"),
                       dict(gut, remote_e2e_fps=True), dict(gut, remote_e2e_fps=0), dict(gut, remote_e2e_fps=-3),
                       dict(gut, remote_e2e_fps=float("nan")), dict(gut, remote_e2e_fps=float("inf")),
                       dict(gut, remote_e2e_fps=10_000), [gut], None):
            with self.subTest(kaputt=kaputt):
                self.assertEqual(code_von(sig.pruefe_quality, kaputt, BID), "quality_ungueltig")


class Antwort(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ProduktiverTransport(unittest.TestCase):
    """HttpsTransport ohne Netz: URL-Grenzen vor jedem Verbindungsaufbau, keine Weiterleitung, Fehlerabbildung."""

    def test_nur_freigegebene_https_urls_ohne_verbindungsaufbau(self):
        t = sig.HttpsTransport()
        for url in ("http://cockpit.insight-it.de/api/signing/artifacts/%s/manifest" % BID,
                    "https://cockpit.insight-it.de.example.invalid/api/signing/artifacts/x",
                    "https://andere.example.invalid/api/signing/artifacts/x",
                    "https://cockpit.insight-it.de:8443/api/signing/artifacts/x",
                    "https://nutzer:pw@cockpit.insight-it.de/api/signing/artifacts/x",
                    "https://cockpit.insight-it.de/api/andere/x", "https://cockpit.insight-it.de:abc/api/signing/x"):
            with self.subTest(url=url):
                self.assertEqual(code_von(t, "GET", url, {}, None, 10), "storage_url")
        self.assertEqual(sig.pruefe_storage_url(BASIS + "/x"), BASIS + "/x")
        self.assertEqual(sig.pruefe_storage_url("https://cockpit.insight-it.de:443/api/signing/health"),
                         "https://cockpit.insight-it.de:443/api/signing/health")

    def test_keine_weiterleitung_und_tls_mindestens_1_2(self):
        t = sig.HttpsTransport()
        weiter = [h for h in t.opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
        self.assertTrue(weiter and all(isinstance(h, sig._KeineWeiterleitung) for h in weiter))
        anfrage = urllib.request.Request(BASIS + "/x", headers={"Authorization": "Bearer " + TOKEN_TEST})
        with self.assertRaises(sig.SigningError) as ctx:
            weiter[0].redirect_request(anfrage, None, 302, "Found", {}, "https://andere.example.invalid/")
        self.assertEqual(ctx.exception.code, "storage_weiterleitung")
        https = [h for h in t.opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertEqual(https[0]._context.minimum_version, __import__("ssl").TLSVersion.TLSv1_2)
        self.assertTrue(https[0]._context.check_hostname)

    def test_anfrage_antwort_und_fehler_mit_gestubbtem_opener(self):
        t = sig.HttpsTransport()
        gesehen = []

        class Opener:
            def __init__(self, ergebnis):
                self.ergebnis = ergebnis

            def open(self, req, timeout):
                gesehen.append((req.get_method(), req.full_url, dict(req.header_items()), req.data, timeout))
                if isinstance(self.ergebnis, Exception):
                    raise self.ergebnis
                return self.ergebnis

        t.opener = Opener(Antwort(b"inhalt"))
        self.assertEqual(t("PUT", BASIS + "/%s/signed" % BID, {"Authorization": "Bearer " + TOKEN_TEST}, b"MZ", 100),
                         (200, b"inhalt"))
        self.assertEqual(gesehen[0][0:2], ("PUT", BASIS + "/%s/signed" % BID))
        self.assertEqual(gesehen[0][3], b"MZ")
        t.opener = Opener(Antwort(b"x" * 101))
        self.assertEqual(code_von(t, "GET", BASIS + "/x", {}, None, 100), "storage_zu_gross")
        t.opener = Opener(urllib.error.HTTPError(BASIS, 409, "Conflict", {}, io.BytesIO(b"geheim")))
        self.assertEqual(t("PUT", BASIS + "/x", {}, b"", 10), (409, b""))
        for exc in (urllib.error.URLError("dns"), ConnectionResetError(), TimeoutError(), socket.timeout()):
            t.opener = Opener(exc)
            self.assertEqual(code_von(t, "GET", BASIS + "/x", {}, None, 10), "storage_nicht_erreichbar")

    def test_auswahl_des_transports(self):
        self.assertIsInstance(sig.storage_transport({}), sig.HttpsTransport)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsInstance(sig.storage_transport({"SIGN_STORAGE_FAKE": tmp}), fake_storage.DateiTransport)
            self.assertEqual(code_von(sig.storage_transport, {"SIGN_STORAGE_FAKE": tmp, "GITHUB_ACTIONS": "true"}),
                             "override_verboten")


class FakeAblageVertrag(unittest.TestCase):
    """Die Fake-Ablage bildet den Vertrag nach – sonst wären Trockenlauf und curl-Tests wertlos."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="Insight Vertrag ")
        self.ablage = fake_storage.FakeAblage.einrichten(self.tmp, TOKEN_TEST, max_groesse=200_000,
                                                         jetzt="2026-11-09T12:00:00+00:00")
        self.exe = tl.baue_installer()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def req(self, methode, pfad, body=None, sha=None, token=TOKEN_TEST, basis=BASIS):
        kopf = {}
        if token is not None:
            kopf["Authorization"] = "Bearer " + token
        if body is not None:
            kopf["X-Artifact-SHA256"] = sha or hashlib.sha256(body).hexdigest()
        return self.ablage.anfrage(methode, basis + pfad, kopf, body)

    def test_upload_download_manifest_loeschen(self):
        q = tl.quality_bytes()
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, self.exe)[0], 201)
        self.assertEqual(self.req("PUT", "/%s/quality" % BID, q)[0], 201)
        self.assertEqual(self.req("GET", "/%s/unsigned" % BID), (200, self.exe))
        status, roh = self.req("GET", "/%s/manifest" % BID)
        m = json.loads(roh)
        self.assertEqual(status, 200)
        self.assertEqual(set(m), {"build_id", "artifacts"})
        self.assertEqual([set(a) for a in m["artifacts"]], [{"kind", "filename", "sha256", "size", "uploaded_at"}] * 2)
        self.assertEqual(sig.pruefe_manifest(m, BID, "quality", hashlib.sha256(q).hexdigest())["size"], len(q))
        self.assertNotIn(self.tmp, roh.decode())
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, self.exe)[0], 409)
        self.assertEqual(self.req("PUT", "/%s/unsigned?replace=1" % BID, tl.baue_installer(saat=3))[0], 201)
        self.assertEqual(self.req("DELETE", "/%s" % BID)[0], 200)
        self.assertEqual(self.req("GET", "/%s/manifest" % BID)[0], 404)
        self.assertEqual(self.req("GET", "/%s/quality" % BID)[0], 404)
        self.assertEqual(self.req("DELETE", "/%s" % BID)[0], 404)

    def test_fehlercodes(self):
        self.assertEqual(self.ablage.anfrage("GET", "https://cockpit.insight-it.de/api/signing/health", {}, None),
                         (200, b'{"ok":true}'))
        self.assertEqual(self.req("GET", "/%s/manifest" % BID, token=None)[0], 401)
        self.assertEqual(self.req("GET", "/%s/manifest" % BID, token="falsch-aber-lang-genug")[0], 401)
        for pfad in ("/../%s/unsigned" % BID, "/2026-11-09/unsigned", "/20261340-120000/unsigned", "/%s/liste" % BID,
                     "/%s/unsigned/x" % BID):
            with self.subTest(pfad=pfad):
                self.assertEqual(self.req("PUT", pfad, self.exe)[0], 400)
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, b"kein PE" * 10)[0], 422)            # Format
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, tl.baue_installer(nsis=False))[0], 422)  # kein NSIS
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, self.exe, sha="0" * 64)[0], 422)      # Hash
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, self.exe, sha="kein-hash")[0], 422)
        for q in (tl.quality_bytes(bestanden=False), tl.quality_bytes(remote_e2e_fps=None),
                  tl.quality_bytes(build_id="20261108-235959"), b"kein json"):
            self.assertEqual(self.req("PUT", "/%s/quality" % BID, q)[0], 422)
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, self.exe + b"\0" * 200_000)[0], 413)
        self.assertEqual(self.req("PUT", "/%s/unsigned?replace=0" % BID, self.exe)[0], 400)
        self.assertEqual(self.req("GET", "/%s/signed" % BID)[0], 404)
        self.ablage.aendere_konfig(token=None)
        self.assertEqual(self.req("GET", "/%s/manifest" % BID)[0], 503)
        self.assertEqual([p["auth"] for p in self.ablage.protokoll()][:3], ["-", "fehlt", "falsch"])
        with open(os.path.join(self.tmp, "protokoll.jsonl"), encoding="utf-8") as fh:
            self.assertNotIn(TOKEN_TEST, fh.read())

    def test_retention_sieben_tage_beim_zugriff(self):
        self.assertEqual(self.req("PUT", "/%s/unsigned" % BID, self.exe)[0], 201)
        self.ablage.aendere_konfig(jetzt="2026-11-16T11:59:59+00:00")
        self.assertEqual(self.req("GET", "/%s/manifest" % BID)[0], 200)
        self.ablage.aendere_konfig(jetzt="2026-11-16T12:00:01+00:00")
        self.assertEqual(self.req("GET", "/%s/manifest" % BID)[0], 404)
        self.assertEqual(os.listdir(os.path.join(self.tmp, "daten")), [])

    def test_datei_transport_mit_echtem_client(self):
        a = sig.Ablage(fake_storage.DateiTransport(self.tmp), TOKEN_TEST)
        sha = hashlib.sha256(self.exe).hexdigest()
        a.lege_ab(BID, "unsigned", self.exe, sha)
        self.assertEqual(sig.pruefe_manifest(a.manifest(BID), BID, "unsigned", sha)["size"], len(self.exe))
        self.assertEqual(a.lade(BID, "unsigned", sig.MAX_GROESSE), self.exe)
        self.assertEqual(code_von(a.lade, BID, "unsigned", 10), "storage_zu_gross")
        self.assertEqual(code_von(a.lege_ab, BID, "unsigned", self.exe, sha), "storage_konflikt")
        self.assertEqual(code_von(sig.Ablage(fake_storage.DateiTransport(self.tmp), "x" * 20).manifest, BID), "storage_token")


class QualityBindung(unittest.TestCase):
    """quality.json ist per Dispatch-Eingabe quality_sha256 an den lokal geprüften Nachweis gebunden."""

    def test_geprueften_nachweis_nur_mit_eingabe_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            pfad = os.path.join(tmp, "qualitaet.json")
            with open(pfad, "w", encoding="utf-8") as fh:
                json.dump({"build_id": BID, "bestanden": True, "remote_e2e_fps": 15.2, "sha256": "c" * 64}, fh)
            self.assertEqual(sig._lies_qualitaet({"qualitaet": pfad}, BID, "c" * 64)["sha256"], "c" * 64)
            self.assertEqual(code_von(sig._lies_qualitaet, {"qualitaet": pfad}, BID, "d" * 64), "quality_abweichung")

    def test_qualitaet_gegen_eingabe_hash(self):
        """Unterbefehl qualitaet: Manifest-Hash und Download müssen = SIGN_QUALITY_SHA256 sein."""
        tmp = tempfile.mkdtemp(prefix="Insight Quality ")
        try:
            ablage = fake_storage.FakeAblage.einrichten(os.path.join(tmp, "Ablage"), TOKEN_TEST)
            echt = tl.quality_bytes()
            ersetzt = tl.quality_bytes(remote_e2e_fps=16.4)          # gültig, bestanden, gleiche Build-ID
            ereignis_pfad = os.path.join(tmp, "ereignis.json")
            with open(ereignis_pfad, "w", encoding="utf-8") as fh:
                json.dump(ereignis(), fh)

            def qualitaet(inhalt, soll):
                ablage.roh_ablegen(BID, "quality", inhalt)
                env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT") if k in os.environ}
                env.update(gueltige_eingaben(SIGN_QUALITY_SHA256=soll), RUNNER_TEMP=tmp, GITHUB_REPOSITORY=REPO_BSP,
                           GITHUB_EVENT_PATH=ereignis_pfad, SIGN_STORAGE_FAKE=os.path.join(tmp, "Ablage"),
                           PYTHONIOENCODING="utf-8", **{"SIGNING_STORAGE_TOKEN": TOKEN_TEST})
                return subprocess.run([sys.executable, os.path.join(SIGNING, "artifact_signing.py"), "qualitaet"], env=env,
                                      capture_output=True, text=True, timeout=60)

            p = qualitaet(echt, hashlib.sha256(echt).hexdigest())
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            os.remove(os.path.join(tmp, "insight-signing", "qualitaet.json"))
            p = qualitaet(ersetzt, hashlib.sha256(echt).hexdigest())
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("FEHLER [quality_abweichung]", p.stderr)
            self.assertFalse(os.path.exists(os.path.join(tmp, "insight-signing", "qualitaet.json")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class Konsistenz(unittest.TestCase):
    def test_ausgaben_pins_und_doku(self):
        self.assertEqual(set(sig.AUSGABEN), set(sig.BEFEHLE))
        with open(DOKU, encoding="utf-8") as fh:
            doku = fh.read()
        with open(WORKFLOW, encoding="utf-8") as fh:
            wf_text = fh.read()
        for name, stand in wc.ACTIONS.items():
            self.assertIn("`%s` %s" % (name, stand["tag"]), doku)
            self.assertIn("%s@%s # %s" % (name, stand["sha"], stand["tag"]), wf_text)
        for befehl in sig.BEFEHLE:
            self.assertIn("artifact_signing.py %s" % befehl, wf_text)
        for code in ("storage_token", "storage_konflikt", "upload_digest", "upload_abweichung", "quality_ungueltig",
                     "repo_unbekannt", "signiert_vorhanden", "download_abweichung"):
            self.assertIn("`%s`" % code, doku)


class YamlTeilmenge(unittest.TestCase):
    def test_unterstuetzte_formen(self):
        text = ('a: 1\nb:\n  - x\n  - "y: z"\n  - k: v\n    l: |\n      eins\n\n      drei\n  - |-\n    roh\n'
                "c: 'it''s'\nd: ~\ne: \"esc\\\"ape\"  # k\nf: wert # kommentar\ng: http://beispiel.invalid/z\nh: -5\ni: true\n")
        self.assertEqual(wc.parse_yaml(text), {"a": 1, "b": ["x", "y: z", {"k": "v", "l": "eins\n\ndrei\n"}, "roh"],
                                               "c": "it's", "d": None, "e": 'esc"ape', "f": "wert", "g": "http://beispiel.invalid/z",
                                               "h": -5, "i": True})

    def test_abgelehnte_formen(self):
        for text in ("a: &x 1\n", "a: *x\n", "a: !t x\n", "a: [1, 2]\n", "a: {b: 1}\n", "a: >\n  x\n", "a:\n\t- x\n",
                     "a: 1\na: 2\n", "---\na: 1\n", "a: b: c\n", "a:\n- x\n", "a: 'offen\n", " a: 1\n", "a: |+\n  x\n"):
            with self.subTest(text=text):
                with self.assertRaises(wc.YamlFehler):
                    wc.parse_yaml(text)

    def test_workflow_gleich_pyyaml_falls_vorhanden(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML nicht installiert (Gegenprobe optional)")
        with open(WORKFLOW, encoding="utf-8") as fh:
            text = fh.read()
        erwartet = yaml.safe_load(text)
        erwartet["on"] = erwartet.pop(True)
        self.assertEqual(wc.parse_yaml(text), erwartet)


class WorkflowPruefung(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(WORKFLOW, encoding="utf-8") as fh:
            cls.gut = fh.read()

    def test_repo_workflow_ohne_befund(self):
        self.assertEqual(wc.pruefe_workflow(self.gut), [])
        p = subprocess.run([sys.executable, os.path.join(SIGNING, "workflow_check.py")], capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        wf = wc.parse_yaml(self.gut)
        self.assertEqual(list(wf["on"]), ["workflow_dispatch"])
        self.assertEqual(wf["jobs"]["signieren"]["needs"], ["tests", "vorpruefung"])
        self.assertEqual(wf["jobs"]["signieren"]["environment"], "release-signing")
        schritte = [s.get("id") for s in wf["jobs"]["signieren"]["steps"]]
        for frueher, spaeter in (("qualitaet", "signieren"), ("vorpruefen", "signieren"), ("signieren", "nachpruefen"),
                                 ("nachpruefen", "hochladen"), ("hochladen", "ablage_pruefen"),
                                 ("ablage_pruefen", "upload_nachweis")):
            self.assertLess(schritte.index(frueher), schritte.index(spaeter))
        # Secret nur im env der Ablage-Schritte, nie bei Actions
        for job in wf["jobs"].values():
            self.assertNotIn("SIGNING_STORAGE_TOKEN", json.dumps(job.get("env") or {}))
            for s in job["steps"]:
                if "uses" in s:
                    self.assertNotIn("secrets.", json.dumps(s))
        self.assertEqual(self.gut.count("${{ secrets.SIGNING_STORAGE_TOKEN }}"), 6)
        eingabe = wf["on"]["workflow_dispatch"]["inputs"]["quality_sha256"]
        self.assertEqual((eingabe["type"], eingabe["required"]), ("string", True))
        for name in ("vorpruefung", "signieren"):
            self.assertEqual(wf["jobs"][name]["env"]["SIGN_QUALITY_SHA256"], "${{ inputs.quality_sha256 }}")
        for verboten in ("gh release", "prerelease", "archive: false", "quality_testrun", "setup-dotnet"):
            self.assertNotIn(verboten, self.gut.lower())

    def mutiere(self, alt, neu):
        self.assertIn(alt, self.gut)
        text = self.gut.replace(alt, neu, 1)
        self.assertNotEqual(text, self.gut)
        return {b["code"] for b in wc.pruefe_workflow(text)}

    def test_mutationen_werden_erkannt(self):
        token_env = "          SIGNING_STORAGE_TOKEN: ${{ secrets.SIGNING_STORAGE_TOKEN }}\n"
        faelle = [
            ("  workflow_dispatch:\n", "  pull_request:\n  workflow_dispatch:\n", {"trigger"}),
            ("  workflow_dispatch:\n", '  push:\n    tags:\n      - "cockpit-v*"\n  workflow_dispatch:\n', {"trigger"}),
            ("run: python tools/signing/artifact_signing.py vorpruefen",
             "run: python tools/signing/artifact_signing.py vorpruefen ${{ inputs.sha256 }}", {"ausdruck_in_run", "reihenfolge"}),
            ("azure/login@" + wc.ACTIONS["azure/login"]["sha"], "azure/login@v3", {"pin"}),
            (wc.ACTIONS["actions/checkout"]["sha"], "1" * 40, {"pin"}),
            ("# v7.0.2", "# v7", {"pin_kommentar"}),
            ("          signing-account-name:", "          signing-account:", {"action_eingabe", "action_konfig"}),
            ('cache-dependencies: "false"', 'cache-dependencies: "true"', {"action_konfig"}),
            ("          file-digest: SHA256\n", "          file-digest: SHA256\n          azure-client-secret: ${{ vars.AZURE_CLIENT_ID }}\n",
             {"action_konfig"}),
            ("    needs:\n      - tests\n      - vorpruefung\n", "", {"needs"}),
            ("        id: nachpruefen\n", "        id: nachpruefen\n        continue-on-error: true\n", {"schema_schluessel"}),
            ("        id: hochladen\n", "        id: hochladen\n        if: always()\n", {"bedingung"}),
            ("        id: abmelden\n        if: always()\n", "        id: abmelden\n", {"bedingung"}),
            ("    environment: release-signing\n", "", {"umgebung"}),
            ("    timeout-minutes: 15\n    permissions:\n      actions: read\n      contents: read\n",
             "    timeout-minutes: 15\n    permissions:\n      actions: read\n      contents: read\n      id-token: write\n", {"rechte"}),
            ("      actions: read\n", "", {"rechte"}),
            ("        id: umgebung\n", "        id: umgebung_alt\n", {"reihenfolge", "schritt_env"}),
            ("permissions:\n  contents: read\n", "permissions:\n  contents: write\n", {"rechte"}),
            ("      - name: Azure-Anmeldung per OIDC", "      - name: Zusatzpaket\n        shell: pwsh\n"
             "        run: python -m pip install requests\n\n      - name: Azure-Anmeldung per OIDC", {"reihenfolge", "pip"}),
            ("          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n",
             "          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n          SIGN_SIGNTOOL: signtool.py\n",
             {"ueberschreibung", "schritt_env"}),
            ("          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n",
             "          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n          SIGN_STORAGE_FAKE: x\n",
             {"ueberschreibung", "schritt_env"}),
            ("name: Fernwartungs-Installer signieren\n", "name: Fernwartungs-Installer signieren\n# Build von build01.example.lan\n",  # scan-ausnahme: Testdaten
             {"intern"}),
            ("name: Fernwartungs-Installer signieren\n", "name: Fernwartungs-Installer signieren\n# Quelle 10.20.30.40\n", {"intern"}),  # scan-ausnahme: Testdaten
            ("timestamp-rfc3161: http://timestamp.acs.microsoft.com", "timestamp-rfc3161: http://timestamp.example.invalid",
             {"action_konfig", "intern"}),
            ("${{ vars.AZURE_CLIENT_ID }}", "${{ secrets.AZURE_CLIENT_ID }}", {"secret_referenz", "ausdruck"}),
            # Secret an falscher Stelle: Action, Job-env, zusätzlicher Schritt, Prüfschritt ohne Ablage
            ("          file-digest: SHA256\n", "          file-digest: SHA256\n          azure-client-secret: ${{ secrets.SIGNING_STORAGE_TOKEN }}\n",
             {"secret_referenz", "secret_ort", "action_konfig"}),
            ("      SIGN_ERSTAUSROLLUNG: ${{ inputs.erstausrollung }}\n    steps:\n      - name: Checkout\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n\n      - name: Eingaben pruefen\n        id: eingaben\n        shell: pwsh",
             "      SIGN_ERSTAUSROLLUNG: ${{ inputs.erstausrollung }}\n      SIGNING_STORAGE_TOKEN: ${{ secrets.SIGNING_STORAGE_TOKEN }}\n    steps:\n      - name: Checkout\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n\n      - name: Eingaben pruefen\n        id: eingaben\n        shell: pwsh",
             {"secret_referenz", "secret_ort", "eingaben_env"}),
            ("        id: vorpruefen\n        shell: bash\n", "        id: vorpruefen\n        shell: bash\n        env:\n" + token_env,
             {"secret_referenz", "secret_ort", "schritt_env"}),
            ("        id: hochladen\n        shell: pwsh\n        env:\n" + token_env, "        id: hochladen\n        shell: pwsh\n",
             {"secret_referenz", "schritt_env"}),
            ("${{ secrets.SIGNING_STORAGE_TOKEN }}", "${{ secrets.GITHUB_TOKEN }}", {"secret_referenz", "ausdruck"}),
            # Release/Installer-Artefakt
            ("          path: ${{ steps.nachpruefen.outputs.nachweis_ordner }}\n",
             "          path: ${{ steps.nachpruefen.outputs.installer }}\n", {"installer_artefakt", "action_konfig"}),
            ("          retention-days: 30\n", "          retention-days: 30\n          archive: false\n",
             {"installer_artefakt", "action_konfig"}),
            ("        run: python tools/signing/artifact_signing.py hochladen",
             "        run: gh release create installer-unsigniert-x datei.exe --prerelease", {"release_verboten", "reihenfolge"}),
            ("          retention-days: 30\n", "          retention-days: 90\n", {"action_konfig"}),
            ("    timeout-minutes: 30\n", "\ttimeout-minutes: 30\n", {"yaml"}),
            ("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    timeout-minutes: 20\n", {"yaml"}),
            ("    timeout-minutes: 15\n", "", {"timeout"}),
            ("${{ steps.vorpruefen.outputs.datei }}", "${{ steps.vorpruefen.outputs.pfad }}", {"ausdruck_ref", "action_konfig"}),
            ("${{ steps.vorpruefen.outputs.datei }}", "${{ steps.nachpruefen.outputs.sha256_signiert }}", {"ausdruck_ref", "action_konfig"}),
            ("SIGN_SHA256: ${{ inputs.sha256 }}", "SIGN_SHA256: ${{ github.event.inputs.sha256 }}", {"ausdruck", "eingaben_env"}),
            ("      SIGN_QUALITY_SHA256: ${{ inputs.quality_sha256 }}\n", "", {"eingaben_env"}),
            ("SIGN_QUALITY_SHA256: ${{ inputs.quality_sha256 }}", "SIGN_QUALITY_SHA256: ${{ inputs.sha256 }}", {"eingaben_env"}),
            ("          file-digest: SHA256\n", "          file-digest: SHA1\n", {"action_konfig"}),
            ("runs-on: windows-2025", "runs-on: windows-latest", {"runner"}),
            ("          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n",
             "          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n          SIGN_GITHUB_SIMULATION: \"1\"\n",
             {"ueberschreibung"}),
            ("          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n",
             "          SIGN_HERAUSGEBER: ${{ vars.ARTIFACT_SIGNING_PUBLISHER }}\n          GITHUB_EVENT_PATH: x.json\n",
             {"ueberschreibung"}),
            ("run: python3 tools/test_artifact_signing.py", "run: python3 tools/test_artifact_signing.py || true", {"reihenfolge"}),
            ("    shell: pwsh\n        run: python tools/signing/artifact_signing.py eingaben",
             "    shell: bash\n        run: python tools/signing/artifact_signing.py eingaben", {"shell"}),
            ("# Fernwartungs-Installer (NSIS)", "# Testwert gh" + "p_" + "A" * 36 + "\n# Fernwartungs-Installer (NSIS)", {"klartext_secret"}),
        ]
        for alt, neu, erwartet in faelle:
            with self.subTest(neu=neu[:90]):
                codes = self.mutiere(alt, neu)
                self.assertTrue(erwartet <= codes, "erwartet %s, gefunden %s" % (erwartet, codes))

    def test_vertauschte_schritte(self):
        start = self.gut.index("      - name: Signierten Installer in der Ablage ablegen")
        ende = self.gut.index("      - name: Ablage pruefen")
        block = self.gut[start:ende]
        ohne = self.gut[:start] + self.gut[ende:]
        ziel = ohne.index("      - name: Nachpruefen (signtool")
        text = ohne[:ziel] + block + ohne[ziel:]
        codes = {b["code"] for b in wc.pruefe_workflow(text)}
        self.assertIn("reihenfolge", codes)


class Trockenlauf(unittest.TestCase):
    """Einmal alle Szenarien (parallel), danach Einzelauswertungen auf denselben Läufen."""

    @classmethod
    def setUpClass(cls):
        cls.wurzel = tempfile.mkdtemp(prefix="Insight Signing Test ")
        cls.laeufe = {lauf.s.name: lauf for lauf in tl.fuehre_parallel(tl.SZENARIEN, cls.wurzel)}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.wurzel, ignore_errors=True)

    def test_alle_szenarien_wie_erwartet(self):
        self.assertGreaterEqual(len(self.laeufe), 50)
        for name, lauf in self.laeufe.items():
            with self.subTest(szenario=name):
                self.assertEqual(tl.bewerte(lauf), [])
        codes = {lauf.s.erwartet[2] for lauf in self.laeufe.values() if lauf.s.erwartet}
        for pflicht in ("digest_abweichung", "build_id_abweichung", "signatur_fehlt",
                        "selbstsigniert", "umgebung_ungeschuetzt", "umgebung_zweige", "umgebung_admin_bypass",
                        "repo_unbekannt", "override_verboten", "zeitstempel_fehlt", "inhalt_geaendert", "signtool_verify",
                        "fake_signtool", "storage_token", "storage_token_fehlt", "storage_nicht_konfiguriert",
                        "storage_fehlt", "quality_fehlt", "quality_ungueltig", "quality_abweichung", "download_abweichung",
                        "signiert_vorhanden", "storage_konflikt", "storage_zu_gross", "storage_abgelehnt", "upload_digest",
                        "upload_abweichung"):
            self.assertIn(pflicht, codes)
        self.assertIsNone(self.laeufe["erfolg_oeffentlich"].s.erwartet)     # öffentliches Repo signiert
        for name, erwartet in (("quality_ersetzt_nach_vorpruefung", ("signieren", "qualitaet", "quality_abweichung")),
                               ("quality_anderer_nachweis", ("vorpruefung", "qualitaet", "quality_abweichung")),
                               ("eingabe_quality_sha256", ("vorpruefung", "eingaben", "eingabe_quality_sha256"))):
            with self.subTest(szenario=name):
                self.assertEqual(self.laeufe[name].s.erwartet, erwartet)
                self.assertEqual(tl.ergebnis(self.laeufe[name]), erwartet)

    def test_erfolg_argumente_ablage_und_hashes(self):
        lauf = self.laeufe["erfolg"]
        datei = lauf.jobs["signieren"]["ausgaben"]["vorpruefen"]["datei"]
        self.assertIn(" ", datei)
        self.assertIn(" ", lauf.signtool)
        self.assertIn("(x86)", lauf.signtool)
        aufrufe = lauf.protokoll(lauf.protokoll_signtool)
        self.assertEqual([a["befehl"] for a in aufrufe], ["sign", "verify"])
        self.assertEqual(aufrufe[0]["argv"][-1], datei)
        self.assertEqual(aufrufe[0]["argv"][aufrufe[0]["argv"].index("/dlib") + 1], lauf.dlib)
        self.assertEqual(aufrufe[1]["argv"], list(sig.SIGNTOOL_VERIFY) + [datei])
        self.assertIn('"%s"' % datei, lauf.aktion_signieren["kommandozeile"])
        gh = [a["argv"] for a in lauf.protokoll(lauf.protokoll_gh)]
        self.assertEqual(gh, [["api", "repos/%s/environments/release-signing" % tl.REPO_NAME],
                              ["api", "repos/%s/environments/release-signing/deployment-branch-policies" % tl.REPO_NAME]])
        anfragen = lauf.ablage_workflow()
        self.assertEqual([(a["methode"], a["pfad"]) for a in anfragen][-3:],
                         [("PUT", "/api/signing/artifacts/%s/signed" % BID), ("GET", "/api/signing/artifacts/%s/manifest" % BID),
                          ("GET", "/api/signing/artifacts/%s/signed" % BID)])
        self.assertTrue(all(a["auth"] == "ok" for a in anfragen))
        ordner = lauf.jobs["signieren"]["ausgaben"]["nachpruefen"]["nachweis_ordner"]
        release, nachweis, bericht = (tl.lies_json(os.path.join(ordner, n)) for n in sig.NACHWEIS_DATEIEN)
        with open(datei, "rb") as fh:
            signiert = fh.read()
        sha_s = hashlib.sha256(signiert).hexdigest()
        self.assertEqual((bericht["sha256_unsigniert"], bericht["sha256_signiert"]), (lauf.sha256, sha_s))
        self.assertEqual(lauf.ablage.inhalt(BID, "signed"), signiert)
        self.assertEqual(bericht["ablage"]["sha256"], sha_s)
        self.assertEqual(bericht["qualitaet"]["remote_e2e_fps"], 15.2)
        self.assertEqual(nachweis["status"], "ungueltig")
        self.assertEqual(release["notiz"].split(";")[0], "TROCKENLAUF – nicht ausrollen")
        self.assertIn("Ablage %s/signed" % BID, release["notiz"])
        sig.pruefe_release_body(release)
        sig.pruefe_nachweis_body(nachweis)
        # Einziges GitHub-Artefakt: die drei JSON-Nachweise
        self.assertEqual([(u["name"], sorted(u["dateien"])) for u in lauf.uploads],
                         [("signatur-nachweis-" + BID, sorted(sig.NACHWEIS_DATEIEN))])

    def test_oeffentliches_repository_signiert_ohne_installer_in_github(self):
        lauf = self.laeufe["erfolg_oeffentlich"]
        self.assertEqual(tl.ergebnis(lauf), None)
        zusammenfassung = lauf.jobs["vorpruefung"]["zusammenfassung"]
        self.assertIn("public", zusammenfassung)
        for u in lauf.uploads:
            self.assertFalse(any(d.endswith(".exe") for d in u["dateien"]))
            self.assertNotIn(b"NullsoftInst", u["inhalt"])

    def test_trockenlauf_ohne_github_kennung(self):
        lauf = self.laeufe["erfolg"]
        env = lauf.umgebung("vorpruefung", lauf.basis, os.devnull, os.devnull, {})
        self.assertNotIn("GITHUB_ACTIONS", env)
        self.assertNotIn("RUNNER_ENVIRONMENT", env)
        self.assertEqual(env["SIGN_GITHUB_SIMULATION"], "1")
        e = tl.lies_json(env["GITHUB_EVENT_PATH"])
        self.assertEqual(sig.pruefe_repo(e, env["GITHUB_REPOSITORY"]), "private")

    def test_kein_signieren_und_kein_upload_vor_bestandener_vorpruefung(self):
        for name, lauf in self.laeufe.items():
            if lauf.s.erwartet and lauf.s.erwartet[1] in tl.SCHRITTE_VOR_SIGNATUR:
                with self.subTest(szenario=name):
                    self.assertEqual([a for a in lauf.protokoll(lauf.protokoll_signtool) if a["befehl"] == "sign"], [])
                    self.assertEqual(lauf.uploads, [])
                    self.assertEqual([a for a in lauf.ablage_workflow() if a["methode"] != "GET"], [])
                    self.assertIsNone(lauf.ablage.inhalt(BID, "signed") if name != "signiert_vorhanden" else None)

    def test_logs_ohne_secrets_token_und_lokale_pfade_in_nachweisen(self):
        for name, lauf in self.laeufe.items():
            text = ""
            for job in lauf.jobs.values():
                text += job["zusammenfassung"]
                for s in job["schritte"]:
                    text += (s.get("stdout") or "") + (s.get("stderr") or "")
            with self.subTest(szenario=name):
                self.assertEqual(wc.scan_secrets(text), [])
                self.assertNotIn(TOKEN_TEST, text)
                self.assertNotIn(lauf.secrets["SIGNING_STORAGE_TOKEN"] or "§§", text)
                self.assertNotIn("trockenlauf-ohne-token", text)
                self.assertNotIn(lauf.vars["AZURE_CLIENT_ID"], text)
                self.assertNotIn(lauf.ablage_ordner, text)
        bericht = tl.bericht_eintrag(self.laeufe["erfolg"], [])
        self.assertNotIn(self.wurzel, json.dumps(bericht, ensure_ascii=False))

    def test_trockenlauf_nachweis_wird_nie_als_echt_akzeptiert(self):
        lauf = self.laeufe["erfolg"]
        ordner = lauf.jobs["signieren"]["ausgaben"]["nachpruefen"]["nachweis_ordner"]
        bericht = tl.lies_json(os.path.join(ordner, "signatur-bericht.json"))
        erwartung = {"build_id": BID, "sha256": lauf.sha256, "version": tl.EINGABEN["version"], "kanal": "pilot",
                     "vorgaenger_id": None, "erstausrollung": True}
        self.assertEqual(code_von(vb.nachweis_pruefen, ordner, tl.REPO_NAME, "4711", erwartung), "nachweis_ungueltig")
        self.assertEqual(code_von(vb.pruefe_bericht, bericht, BID, lauf.sha256), "nachweis_ungueltig")
        echt = dict(bericht, trockenlauf=False)
        self.assertEqual(vb.pruefe_bericht(echt, BID, lauf.sha256)["ablage"]["sha256"], bericht["sha256_signiert"])


REPO_BSP = "beispiel/cockpit-signing"
LAUF_URL = "https://github.com/%s/actions/runs/4711/attempts/1" % REPO_BSP


def lege_quelle(tmp, data=None, quality=None):
    quelle = os.path.join(tmp, "Kunde Beispiel", "insight-fernwartung-kunde-beispiel.exe")
    os.makedirs(os.path.dirname(quelle), exist_ok=True)
    with open(quelle, "wb") as fh:
        fh.write(tl.baue_installer() if data is None else data)
    q = os.path.join(tmp, "Kunde Beispiel", "quality (lauf).json")
    with open(q, "wb") as fh:
        fh.write(tl.quality_bytes() if quality is None else quality)
    return quelle, q


class Vorbereiten(unittest.TestCase):
    def test_kopien_und_befehle(self):
        tmp = tempfile.mkdtemp(prefix="Insight Vorbereiten ")
        try:
            quelle, q = lege_quelle(tmp)
            data = tl.baue_installer()
            ziel = os.path.join(tmp, "Ausgang mit Leerzeichen")
            e, kopie, befehle = vb.vorbereiten(quelle, q, "2026.11.1", "pilot", None, True, ziel, REPO_BSP)
            self.assertEqual(os.path.basename(kopie), "insight-fernwartung-%s.unsigniert.exe" % BID)
            self.assertNotIn("kunde-beispiel", os.path.basename(kopie))
            self.assertFalse(os.path.exists(os.path.join(ziel, sig.asset_name(BID))))
            with open(os.path.join(ziel, "quality-%s.json" % BID), "rb") as fh:
                self.assertEqual(fh.read(), tl.quality_bytes())
            sha, sha_q = hashlib.sha256(data).hexdigest(), hashlib.sha256(tl.quality_bytes()).hexdigest()
            self.assertIn("-f build_id=%s -f sha256=%s -f quality_sha256=%s -f version=2026.11.1 -f kanal=pilot "
                          "-f erstausrollung=true" % (BID, sha, sha_q), befehle)
            self.assertIn("ABLAGE=%s" % BASIS, befehle)
            self.assertIn("-X PUT -H @- -H 'X-Artifact-SHA256: %s' -H 'Content-Type: application/octet-stream' "
                          "--data-binary @'%s' \"$ABLAGE/%s/unsigned\"" % (sha, kopie, BID), befehle)
            self.assertIn("-H 'X-Artifact-SHA256: %s' -H 'Content-Type: application/json'" % sha_q, befehle)
            self.assertIn("manifest-pruefen %s %s %s" % (BID, sha, sha_q), befehle)
            self.assertIn("\"$ABLAGE/%s/signed\"" % BID, befehle)
            pruefe_befehle(self, befehle, REPO_BSP)
            p = subprocess.run([sys.executable, os.path.join(SIGNING, "vorbereiten.py"), quelle, "--quality", q,
                                "--version", "2026.11.1", "--vorgaenger-id", "R-0123456789ab", "--ziel", ziel, "--repo", REPO_BSP],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("-f vorgaenger_id=R-0123456789ab", p.stdout)
            self.assertIn(" 2026.11.1 pilot R-0123456789ab", p.stdout)
            for kaputt, code in ((fake_signtool.signiere_bytes(data, {"kette": [], "zeitstempel": None}), "bereits_signiert"),
                                 (tl.baue_installer(nsis=False), "kein_nsis")):
                with open(quelle, "wb") as fh:
                    fh.write(kaputt)
                self.assertEqual(code_von(vb.vorbereiten, quelle, q, "2026.11.1", "pilot", None, True, ziel, "a/b"), code)
            with open(quelle, "wb") as fh:
                fh.write(data)
            for kaputt in (tl.quality_bytes(bestanden=False), tl.quality_bytes(remote_e2e_fps=None),
                           tl.quality_bytes(build_id="20261108-235959"), b"kein json", b"{" * (sig.MAX_QUALITY + 1)):
                with self.subTest(quality=kaputt[:40]):
                    with open(q, "wb") as fh:
                        fh.write(kaputt)
                    self.assertEqual(code_von(vb.vorbereiten, quelle, q, "2026.11.1", "pilot", None, True, ziel, REPO_BSP),
                                     "quality_ungueltig")
            p = subprocess.run([sys.executable, os.path.join(SIGNING, "vorbereiten.py"), quelle, "--quality", q,
                                "--version", "2026.11.1", "--erstausrollung", "--ziel", ziel, "--repo", REPO_BSP],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual((p.returncode, p.stdout), (1, ""))
            self.assertIn("FEHLER [quality_ungueltig]", p.stderr)
            gleich = os.path.join(ziel, "insight-fernwartung-%s.unsigniert.exe" % BID)
            with open(q, "wb") as fh:
                fh.write(tl.quality_bytes())
            self.assertEqual(code_von(vb.vorbereiten, gleich, q, "2026.11.1", "pilot", None, True, ziel, REPO_BSP),
                             "ziel_gleich_quelle")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_manifest_pruefen(self):
        sha, sha_q = "b" * 64, "c" * 64
        gut = manifest(unsigned=(sha, 10), quality=(sha_q, 5))
        self.assertIs(vb.manifest_pruefen(gut, BID, sha, sha_q), gut)
        faelle = {"ablage_abweichung": [manifest(unsigned=("d" * 64, 10), quality=(sha_q, 5)),
                                        manifest(unsigned=(sha, 10), quality=("d" * 64, 5))],
                  "quality_fehlt": [manifest(unsigned=(sha, 10))], "asset_fehlt": [manifest(quality=(sha_q, 5))],
                  "signiert_vorhanden": [manifest(unsigned=(sha, 10), quality=(sha_q, 5), signed=("e" * 64, 12))]}
        for code, varianten in faelle.items():
            for m in varianten:
                with self.subTest(code=code):
                    self.assertEqual(code_von(vb.manifest_pruefen, m, BID, sha, sha_q), code)


def pruefe_befehle(test, befehle, repo):
    """Kein Release, Token nie als Argument, Ablage nur per curl mit --proto =https, Lauf genau einmal, Aufräumen."""
    zeilen = [z.strip() for z in befehle.splitlines() if z.strip() and not z.strip().startswith("#")]
    test.assertNotIn("gh release", befehle)
    test.assertNotIn("installer-unsigniert-", befehle)
    test.assertNotIn("actions/artifacts", befehle)
    test.assertNotIn("<", befehle.replace("<<", ""))                     # keine Platzhalter
    test.assertNotIn("$SIGNING_STORAGE_TOKEN\"", " ".join(z for z in zeilen if z.startswith("curl") or "| curl" in z))
    curls = [z for z in zeilen if "curl " in z]
    # health, 2× PUT, manifest, GET signed; in den Funktionen: Manifest vor dem Löschen, DELETE
    test.assertEqual(len(curls), 7, curls)
    for z in curls:
        test.assertEqual(z.count("curl "), 1, z)
        teil = z[z.index("curl "):]
        test.assertTrue(teil.startswith("curl --proto =https --tlsv1.2 -fsS"), z)
        test.assertNotIn("Authorization", teil)
        test.assertNotIn("SIGNING_STORAGE_TOKEN", teil)
        test.assertNotIn("-k", teil.split())
        test.assertNotIn("--insecure", teil)
        if "health" not in teil:
            test.assertIn("ablage_kopf | curl ", z)                     # Token nur über ablage_kopf (stdin)
            test.assertIn("-H @-", teil)
    test.assertIn("ablage_kopf() { printf 'Authorization: Bearer %s\\n' \"${SIGNING_STORAGE_TOKEN:?}\"; }", zeilen)
    test.assertEqual(sum("--data-binary" in z for z in zeilen), 2)
    downloads = [z for z in zeilen if "gh run download" in z]
    test.assertEqual(len(downloads), 1, downloads)
    test.assertIn("--name signatur-nachweis-%s" % BID, downloads[0])
    test.assertNotIn("--limit 1 ", befehle)
    listen = [z for z in zeilen if "gh run list" in z]
    test.assertEqual(len(listen), 2, listen)
    for liste in listen:
        for teil in ("--workflow sign-cockpit.yml", "--event workflow_dispatch", "--branch main",
                     "databaseId,displayTitle,event,headBranch,workflowName"):
            test.assertIn(teil, liste)
    test.assertTrue(listen[0].startswith("VORHER=\"$(") and "laeufe-vorher %s" % BID in listen[0], listen[0])
    test.assertTrue(listen[1].startswith("LAUF=\"$(") and "lauf-id %s \"${VORHER:?" % BID in listen[1], listen[1])
    reihenfolge = ["trap aufraeumen EXIT", "/api/signing/health", "/unsigned\"", "HOCHGELADEN=1", "/quality\"",
                   "manifest-pruefen", "laeufe-vorher", "GESTARTET=1", "gh workflow run", "lauf-id", "gh run watch",
                   "LAUF_OK=1",
                   "gh run download", "nachweis-pruefen", "/signed\"", "ergebnis-pruefen"]
    positionen = [befehle.index(t, befehle.index("trap aufraeumen EXIT")) for t in reihenfolge]
    test.assertEqual(positionen, sorted(positionen), reihenfolge)
    test.assertEqual(zeilen[-1], "aufraeumen")
    kopf = [z for z in befehle.splitlines() if z.startswith("# ") and "Aufräumen" in z]
    test.assertEqual(len(kopf), 1, kopf)
    test.assertIn("IMMER", kopf[0])
    test.assertEqual(sum("-X DELETE" in z for z in zeilen), 1)
    # Löschen nur über die Prüfung loeschen_erlaubt (Lauf-Ausgang per gh run view + Manifest), nie allein nach Flags
    test.assertIn("if [ \"$HOCHGELADEN\" = 1 ] && [ \"$LAUF_OK\" != 1 ] && loeschen_erlaubt; then", zeilen)
    test.assertIn("loeschen-pruefen %s" % BID, befehle)
    test.assertIn("gh run view --repo %s" % repo, befehle)
    # HOCHGELADEN / GESTARTET / LAUF_OK nur abhängig vom Exit-Code (auch ohne set -e): nie als eigene Zeile
    for flag in ("HOCHGELADEN=1", "LAUF_OK=1"):
        test.assertNotIn(flag, zeilen)
        test.assertEqual(sum(flag in z for z in zeilen), 1, flag)
    test.assertTrue([z for z in zeilen if "/unsigned\"" in z][0].startswith("if ablage_kopf | curl "))
    test.assertIn("then HOCHGELADEN=1; else exit 1; fi", befehle)
    test.assertTrue([z for z in zeilen if z.startswith("if gh run watch")][0].endswith("then LAUF_OK=1; else exit 1; fi"))
    test.assertLess(befehle.index("GESTARTET=1"), befehle.index("gh workflow run"))
    # jeder Prüf-/Netzbefehl nach Block 0 bricht auch ohne set -e ab
    rumpf = zeilen[zeilen.index("trap aufraeumen EXIT") + 1:-1]
    for z in rumpf:
        if z.startswith(("echo ", "GESTARTET=", "sleep ")):
            continue
        test.assertTrue(z.endswith(("|| exit 1", "; exit 1; }", "; else exit 1; fi")), z)


def lauf(nummer, build_id=BID, **aenderung):
    eintrag = {"databaseId": nummer, "displayTitle": "Installer signieren %s" % build_id, "event": "workflow_dispatch",
               "headBranch": "main", "workflowName": "Fernwartungs-Installer signieren"}
    eintrag.update(aenderung)
    return eintrag


ERWARTUNG = {"build_id": BID, "sha256": hashlib.sha256(tl.baue_installer()).hexdigest(), "version": "2026.11.1",
             "kanal": "pilot", "vorgaenger_id": None, "erstausrollung": True}


def signiertes_ergebnis():
    """Signierter (Fake-)Installer und Signaturbericht wie aus Nachprüfung + ablage-pruefen (echter Lauf 4711)."""
    unsigniert = tl.baue_installer()
    signiert = fake_signtool.signiere_bytes(unsigniert, {"kette": [], "zeitstempel": None})
    sha_s = hashlib.sha256(signiert).hexdigest()
    bericht = {"format": sig.BERICHT_FORMAT, "asset": sig.asset_name(BID), "build_id": BID,
               "sha256_unsigniert": hashlib.sha256(unsigniert).hexdigest(), "sha256_signiert": sha_s,
               "groesse_unsigniert": len(unsigniert), "groesse_signiert": len(signiert), "trockenlauf": False,
               "qualitaet": {"build_id": BID, "bestanden": True, "remote_e2e_fps": 15.2,
                             "sha256": hashlib.sha256(tl.quality_bytes()).hexdigest()},
               "git_sha": "c" * 40, "lauf_url": LAUF_URL,
               "ablage": {"build_id": BID, "kind": "signed", "dateiname": sig.asset_name(BID), "sha256": sha_s,
                          "groesse": len(signiert), "uploaded_at": "2026-11-09T12:30:00+00:00"}}
    return signiert, bericht


def nachweis_dateien(bericht, release=None, nachweis=None):
    """Die drei Nachweisdateien eines echten Laufs (Form wie artifact_signing.cmd_nachpruefen)."""
    rel = {"version": "2026.11.1", "git_sha": bericht["git_sha"], "build_id": bericht["build_id"], "kanal": "pilot",
           "artefakte": [{"name": bericht["asset"], "sha256": bericht["sha256_signiert"], "groesse": bericht["groesse_signiert"]}],
           "vorgaenger_id": None, "erstausrollung": True, "symbole": [],
           "notiz": "Signiert mit Microsoft Artifact Signing; Ablage %s/signed; remote_e2e_fps 15.2" % bericht["build_id"]}
    rel.update(release or {})
    nw = {"artefakt": bericht["asset"], "sha256": bericht["sha256_signiert"], "status": "gueltig",
          "aussteller": "Microsoft ID Verified CS AOC CA 04; Inhaber Beispiel GmbH", "zeitstempel": True,
          "werkzeug": "signtool verify /pa /tw /v", "lauf_url": bericht["lauf_url"]}
    nw.update(nachweis or {})
    return {"release-metadata.json": rel, "signatur-nachweis.json": nw, "signatur-bericht.json": bericht}


def schreibe_nachweis(ordner, dateien):
    os.makedirs(ordner, exist_ok=True)
    for name, obj in dateien.items():
        with open(os.path.join(ordner, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
    return ordner


FAKE_GH = r"""
import json, os, sys
a = sys.argv[1:]
with open(os.environ["FG_PROTOKOLL"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(a) + "\n")
daten = json.load(open(os.environ["FG_DATEN"], encoding="utf-8"))
if a[:1] == ["release"] or (a[:1] == ["api"] and "releases" in " ".join(a)):
    print("Release-Aufruf verboten", file=sys.stderr); sys.exit(97)
if a[:2] == ["run", "list"]:
    zaehler = os.environ["FG_PROTOKOLL"] + ".runlist"
    n = int(open(zaehler).read()) if os.path.exists(zaehler) else 0
    open(zaehler, "w").write(str(n + 1))
    folge = daten["laeufe_folge"]
    print(json.dumps(folge[min(n, len(folge) - 1)])); sys.exit(0)
if a[:2] == ["run", "watch"]:
    if daten.get("signieren"):   # der Workflow legt den signierten Installer in der Ablage ab
        import shutil
        bid = daten["build_id"]
        ordner = os.path.join(os.environ["FAKE_STORAGE_ORDNER"], "daten", bid)
        sys.path.insert(0, os.environ["FG_SIGNING"])
        import fake_storage
        fake_storage.FakeAblage(os.environ["FAKE_STORAGE_ORDNER"], quelle="workflow").roh_ablegen(
            bid, "signed", open(daten["installer"], "rb").read())
    if "watch_exit" in daten:    # nur die Beobachtung scheitert (Netz, Strg-C, Terminal zu) – Lauf läuft weiter
        sys.exit(daten["watch_exit"])
    sys.exit(0 if a[-2] == daten["lauf"] and daten.get("lauf_gruen", True) else 1)
if a[:2] == ["run", "view"]:
    if "--json" not in a or "conclusion" not in a[a.index("--json") + 1].split(","):
        sys.exit(2)
    stand = daten.get("lauf_stand", "standard")
    if stand == "fehler":
        print("HTTP 502: Bad Gateway", file=sys.stderr); sys.exit(1)
    if stand == "standard":
        stand = {"databaseId": int(daten["lauf"]), "status": "completed",
                 "conclusion": "success" if daten.get("lauf_gruen", True) else "failure"}
    print(json.dumps(stand)); sys.exit(0)
if a[:2] == ["workflow", "run"]:
    sys.exit(0)
if a[:2] == ["run", "download"]:
    if "--name" not in a:
        sys.exit(1)
    name, ziel = a[a.index("--name") + 1], a[a.index("--dir") + 1]
    if name != "signatur-nachweis-" + daten["build_id"] or a[4] not in daten["nachweise"]:
        sys.exit(1)
    os.makedirs(ziel, exist_ok=True)
    for datei, obj in daten["nachweise"][a[4]].items():
        json.dump(obj, open(os.path.join(ziel, datei), "w", encoding="utf-8"))
    sys.exit(0)
print("unbekannter gh-Aufruf", file=sys.stderr); sys.exit(2)
"""


class VorbereitenErgebnisLaden(unittest.TestCase):
    """Lauf eindeutig und neu, Nachweis an Dispatch-Werte gebunden, Installer aus der Ablage laden und prüfen."""

    def test_lauf_einmal_gefiltert_aus_mehreren(self):
        andere = [lauf(9), lauf(8, build_id="20261109-120001"), lauf(7, event="push"), lauf(6, headBranch="feature"),
                  lauf(5, workflowName="Anderer Workflow"), lauf(4, displayTitle="Installer signieren %s x" % BID)]
        self.assertEqual(vb.lauf_aufloesen([lauf(10, build_id="20261109-120001")] + andere[1:] + [lauf(3)], BID), "3")
        self.assertEqual(vb.lauf_aufloesen([lauf(3), lauf(3)], BID), "3")
        self.assertEqual(code_von(vb.lauf_aufloesen, andere[1:], BID), "lauf_fehlt")
        self.assertEqual(code_von(vb.lauf_aufloesen, [], BID), "lauf_fehlt")
        self.assertEqual(code_von(vb.lauf_aufloesen, [lauf(3), lauf(11)], BID), "lauf_mehrdeutig")
        for kaputt in ({"x": 1}, None, [lauf("3; rm")], [lauf(True)], [lauf(-3)]):
            with self.subTest(kaputt=kaputt):
                self.assertIn(code_von(vb.lauf_aufloesen, kaputt, BID), ("lauf_liste", "lauf_fehlt"))
        self.assertEqual(code_von(vb.lauf_aufloesen, [lauf(3)], "x"), "eingabe_build_id")

    def test_aeltere_laeufe_derselben_build_id_nie_gewaehlt(self):
        self.assertEqual(vb.laeufe_vorher([lauf(4700), lauf(4690), lauf(4701, build_id="20261109-120001")], BID),
                         {"4690", "4700"})
        self.assertEqual(vb.laeufe_vorher([], BID), set())
        self.assertEqual(code_von(vb.lauf_aufloesen, [lauf(4700)], BID, {"4700"}), "lauf_fehlt")
        self.assertEqual(vb.lauf_aufloesen([lauf(4711), lauf(4700)], BID, {"4700"}), "4711")
        self.assertEqual(code_von(vb.lauf_aufloesen, [lauf(4711), lauf(4712), lauf(4700)], BID, {"4700"}), "lauf_mehrdeutig")
        self.assertEqual(code_von(vb.laeufe_vorher, None, BID), "lauf_liste")

    def test_nachweis_an_lauf_und_dispatch_werte_gebunden(self):
        _s, bericht = signiertes_ergebnis()
        tmp = tempfile.mkdtemp(prefix="Insight Nachweis ")
        try:
            def pruefe(dateien, lauf_id="4711", erwartung=ERWARTUNG):
                ordner = schreibe_nachweis(os.path.join(tmp, "n%d" % len(os.listdir(tmp))), dateien)
                return vb.nachweis_pruefen(ordner, REPO_BSP, lauf_id, erwartung)

            self.assertEqual(pruefe(nachweis_dateien(bericht))["sha256_signiert"], bericht["sha256_signiert"])
            alt_bericht = dict(bericht, sha256_unsigniert="d" * 64)
            faelle = {
                "nachweis_abweichung": [
                    (nachweis_dateien(bericht, release={"version": "2026.11.0"}), "4711", ERWARTUNG),
                    (nachweis_dateien(bericht, release={"kanal": "produktiv"}), "4711", ERWARTUNG),
                    (nachweis_dateien(bericht, release={"vorgaenger_id": "R-0123456789ab", "erstausrollung": False}),
                     "4711", ERWARTUNG),
                    (nachweis_dateien(bericht), "4700", ERWARTUNG),
                    (nachweis_dateien(bericht, nachweis={"sha256": "e" * 64}), "4711", ERWARTUNG),
                    (nachweis_dateien(bericht, release={"artefakte": [{"name": bericht["asset"], "sha256": "e" * 64,
                                                                        "groesse": 1}]}), "4711", ERWARTUNG),
                    (nachweis_dateien(bericht), "4711", dict(ERWARTUNG, version="2026.11.2")),
                    (nachweis_dateien(alt_bericht), "4711", ERWARTUNG)],
                "nachweis_ungueltig": [
                    (nachweis_dateien(bericht, nachweis={"status": "ungueltig"}), "4711", ERWARTUNG),
                    (nachweis_dateien(dict(bericht, trockenlauf=True)), "4711", ERWARTUNG),
                    (nachweis_dateien(bericht, release={"notiz": "TROCKENLAUF – nicht ausrollen"}), "4711", ERWARTUNG),
                    (nachweis_dateien(dict(bericht, lauf_url="")), "4711", ERWARTUNG),
                    (nachweis_dateien(dict(bericht, ablage=None)), "4711", ERWARTUNG),
                    (nachweis_dateien(dict(bericht, ablage=dict(bericht["ablage"], sha256="e" * 64))), "4711", ERWARTUNG),
                    (nachweis_dateien(dict(bericht, qualitaet=None)), "4711", ERWARTUNG),
                    (nachweis_dateien(dict(bericht, format="insight-artifact-signing/1")), "4711", ERWARTUNG)],
            }
            for code, varianten in faelle.items():
                for dateien, lauf_id, erwartung in varianten:
                    with self.subTest(code=code, lauf=lauf_id):
                        self.assertEqual(code_von(pruefe, dateien, lauf_id, erwartung), code)
            unvollstaendig = nachweis_dateien(bericht)
            del unvollstaendig["release-metadata.json"]
            self.assertEqual(code_von(pruefe, unvollstaendig), "nachweis_fehlt")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_lauf_titel_passt_zum_workflow(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            wf = wc.parse_yaml(fh.read())
        self.assertEqual(wf["run-name"], vb.LAUF_TITEL % "${{ inputs.build_id }}")
        self.assertEqual(wf["name"], vb.WORKFLOW_NAME)

    def test_ergebnis_pruefen(self):
        signiert, bericht = signiertes_ergebnis()
        sha_u = bericht["sha256_unsigniert"]
        tmp = tempfile.mkdtemp(prefix="Insight Ergebnis ")
        try:
            def lade(inhalt, ziel=os.path.join(tmp, "Ausgang (signiert)"), erwartet_u=sha_u):
                roh = os.path.join(tmp, "download.bin")
                with open(roh, "wb") as fh:
                    fh.write(inhalt)
                return vb.ergebnis_pruefen(roh, bericht, ziel, erwartet_u)

            pfad = lade(signiert)
            self.assertEqual(os.path.basename(pfad), sig.asset_name(BID))
            with open(pfad, "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), bericht["sha256_signiert"])
            manipuliert = bytearray(signiert)
            manipuliert[700] ^= 1
            for inhalt in (bytes(manipuliert), signiert + b"\0", tl.baue_installer(), b""):
                with self.subTest(n=len(inhalt)):
                    os.remove(pfad)
                    self.assertEqual(code_von(lade, inhalt), "sha256_abweichung")
                    self.assertFalse(os.path.exists(pfad))
                    with open(pfad, "wb") as fh:
                        fh.write(b"alt")
            with open(pfad, "rb") as fh:
                self.assertEqual(fh.read(), b"alt")
            self.assertEqual(code_von(lade, signiert, erwartet_u="d" * 64), "nachweis_abweichung")
            unsigniert = tl.baue_installer()
            ohne_sig = dict(bericht, sha256_signiert=hashlib.sha256(unsigniert).hexdigest(), groesse_signiert=len(unsigniert))
            ohne_sig["ablage"] = dict(bericht["ablage"], sha256=ohne_sig["sha256_signiert"], groesse=len(unsigniert))
            roh = os.path.join(tmp, "u.bin")
            with open(roh, "wb") as fh:
                fh.write(unsigniert)
            self.assertEqual(code_von(vb.ergebnis_pruefen, roh, ohne_sig, tmp, sha_u), "signatur_fehlt")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ---------- gedruckte Befehle Ende-zu-Ende unter bash -euo pipefail (curl- und gh-Double, Fake-Ablage)
    def umgebung(self, tmp, daten, token=TOKEN_TEST):
        bin_ordner = os.path.join(tmp, "bin")
        os.makedirs(bin_ordner, exist_ok=True)
        skripte = (("gh", "#!%s\n%s" % (sys.executable, FAKE_GH)), ("sleep", "#!/bin/sh\nexit 0\n"),
                   ("curl", "#!/bin/sh\nexec %s %s curl \"$@\"\n" % (sys.executable, os.path.join(SIGNING, "fake_storage.py"))))
        for name, inhalt in skripte:
            with open(os.path.join(bin_ordner, name), "w", encoding="utf-8") as fh:
                fh.write(inhalt)
            os.chmod(os.path.join(bin_ordner, name), 0o755)
        with open(os.path.join(tmp, "daten.json"), "w", encoding="utf-8") as fh:
            json.dump(daten, fh)
        protokoll = os.path.join(tmp, "protokoll.jsonl")
        for alt in (protokoll, protokoll + ".runlist"):
            if os.path.exists(alt):
                os.remove(alt)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "RUNNER_", "SIGNING_"))}
        env.update(PATH=bin_ordner + os.pathsep + os.environ.get("PATH", ""), FG_DATEN=os.path.join(tmp, "daten.json"),
                   FG_PROTOKOLL=protokoll, FG_SIGNING=SIGNING, FAKE_STORAGE_ORDNER=os.path.join(tmp, "Ablage"))
        if token is not None:
            env["SIGNING_STORAGE_TOKEN"] = token
        return env

    def gh_aufrufe(self, tmp):
        pfad = os.path.join(tmp, "protokoll.jsonl")
        if not os.path.exists(pfad):
            return []
        with open(pfad, encoding="utf-8") as fh:
            return [json.loads(z) for z in fh]

    def test_gedruckte_befehle_laufen_gegen_fake_ablage(self):
        signiert, bericht = signiertes_ergebnis()
        tmp = tempfile.mkdtemp(prefix="Insight Fake curl ")
        try:
            quelle, q = lege_quelle(tmp)
            ziel = os.path.join(tmp, "Ausgang (Test)")
            name = sig.asset_name(BID)
            installer = os.path.join(tmp, "signiert.bin")
            with open(installer, "wb") as fh:
                fh.write(signiert)
            alt_bericht = dict(bericht, lauf_url=LAUF_URL.replace("4711", "4700"))
            basis = {"build_id": BID, "lauf": "4711", "installer": installer, "signieren": True,
                     "nachweise": {"4711": nachweis_dateien(bericht), "4700": nachweis_dateien(alt_bericht)},
                     "laeufe_folge": [[lauf(4700), lauf(4699, build_id="20261109-120001")],
                                      [lauf(4711), lauf(4712, build_id="20261109-120001"), lauf(4700), lauf(4690, event="push")]]}
            ablage_ordner = os.path.join(tmp, "Ablage")

            def ausfuehren(token=TOKEN_TEST, server_token=TOKEN_TEST, vorbelegt=None, **aenderung):
                shutil.rmtree(ablage_ordner, ignore_errors=True)
                ablage = fake_storage.FakeAblage.einrichten(ablage_ordner, server_token)
                for kind, daten in (vorbelegt or {}).items():
                    ablage.roh_ablegen(BID, kind, daten)
                _e, kopie, befehle = vb.vorbereiten(quelle, q, "2026.11.1", "pilot", None, True, ziel, "beispiel/cockpit-signing")
                env = self.umgebung(tmp, dict(basis, **aenderung), token)
                p = subprocess.run(["bash", "-euo", "pipefail", "-c", befehle], capture_output=True, text=True, env=env,
                                   timeout=120)
                return p, kopie, self.gh_aufrufe(tmp), ablage

            ergebnis = os.path.join(ziel, "signiert-%s" % BID, name)

            def aufgeraeumt(kopie):
                self.assertFalse(os.path.exists(kopie))
                self.assertFalse(os.path.exists(os.path.join(ziel, "quality-%s.json" % BID)))
                self.assertFalse(os.path.exists(os.path.join(ziel, "signiert-%s" % BID, "download.bin")))

            def ablage_anfragen(ablage):
                return [(a["methode"], a["pfad"].rsplit("/", 1)[-1], a["status"], a["auth"])
                        for a in ablage.protokoll() if a["quelle"] == "curl"]

            # Erfolg: hochladen, Manifest prüfen, Lauf, Nachweis, Download prüfen – keine Löschung nach Erfolg
            p, kopie, aufrufe, ablage = ausfuehren()
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            with open(ergebnis, "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), bericht["sha256_signiert"])
            self.assertEqual(ablage_anfragen(ablage), [
                ("GET", "health", 200, "-"), ("PUT", "unsigned", 201, "ok"), ("PUT", "quality", 201, "ok"),
                ("GET", "manifest", 200, "ok"), ("GET", "signed", 200, "ok")])
            self.assertEqual(ablage.inhalt(BID, "unsigned"), tl.baue_installer())
            self.assertEqual(ablage.inhalt(BID, "quality"), tl.quality_bytes())
            self.assertIsNotNone(ablage.inhalt(BID, "signed"))             # bleibt bis zur Retention
            self.assertIn("nicht von Hand löschen", p.stderr)
            self.assertFalse([a for a in aufrufe if a[:1] == ["release"]])
            self.assertEqual(sum(a[:2] == ["run", "list"] for a in aufrufe), 2)
            self.assertNotIn(TOKEN_TEST, p.stdout + p.stderr + json.dumps(aufrufe))
            aufgeraeumt(kopie)

            # Token fehlt in der Shell → Abbruch vor jedem Upload, nichts zu löschen
            os.remove(ergebnis)
            p, kopie, aufrufe, ablage = ausfuehren(token=None)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("SIGNING_STORAGE_TOKEN", p.stderr)
            self.assertEqual(ablage_anfragen(ablage), [])
            aufgeraeumt(kopie)

            # Falsches Token → 401 beim ersten PUT, kein DELETE, kein Workflow-Start
            p, kopie, aufrufe, ablage = ausfuehren(token="falsches-token-0123456789")
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("401", p.stderr)
            self.assertEqual([a[:2] for a in ablage_anfragen(ablage)], [("GET", "health"), ("PUT", "unsigned")])
            self.assertFalse([a for a in aufrufe if a[:2] == ["workflow", "run"]])
            aufgeraeumt(kopie)

            # Build existiert schon (z. B. früherer Erfolg mit signed) → 409, NIE löschen
            vorher = fake_signtool.signiere_bytes(tl.baue_installer(), {"kette": [], "zeitstempel": None})
            p, kopie, aufrufe, ablage = ausfuehren(vorbelegt={"unsigned": tl.baue_installer(), "signed": vorher})
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("409", p.stderr)
            self.assertFalse([a for a in ablage_anfragen(ablage) if a[0] == "DELETE"])
            self.assertEqual(ablage.inhalt(BID, "signed"), vorher)
            aufgeraeumt(kopie)

            # Race: Lauf gestartet, aber nicht bestimmbar → Ausgang unbekannt → nichts löschen (Retention)
            p, kopie, aufrufe, ablage = ausfuehren(laeufe_folge=[[lauf(4700)], [lauf(4700)]])
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("lauf_fehlt", p.stderr)
            self.assertFalse([a for a in aufrufe if a[:2] in (["run", "watch"], ["run", "download"])])
            self.assertFalse([a for a in ablage_anfragen(ablage) if a[0] == "DELETE"])
            self.assertIsNotNone(ablage.inhalt(BID, "unsigned"))
            self.assertIn("nicht von Hand löschen", p.stderr)
            aufgeraeumt(kopie)

            # Roter Lauf (gh run view: completed/failure), kein signed → eigener Upload gelöscht, kein Download
            p, kopie, aufrufe, ablage = ausfuehren(lauf_gruen=False, signieren=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(ablage_anfragen(ablage)[-2:], [("GET", "manifest", 200, "ok"), ("DELETE", BID, 200, "ok")])
            self.assertIn(["run", "view", "--repo", "beispiel/cockpit-signing", "4711", "--json",
                           "databaseId,status,conclusion"], aufrufe)
            self.assertFalse([a for a in aufrufe if a[:2] == ["run", "download"]])
            aufgeraeumt(kopie)

            # Grüner Lauf, aber Nachweis passt nicht → Abbruch vor dem Download, KEINE Löschung nach grünem Lauf
            p, kopie, aufrufe, ablage = ausfuehren(nachweise={"4711": nachweis_dateien(bericht, release={"kanal": "produktiv"})})
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("nachweis_abweichung", p.stderr)
            self.assertFalse([a for a in ablage_anfragen(ablage) if a[0] == "DELETE" or a[1] == "signed"])
            self.assertIsNotNone(ablage.inhalt(BID, "signed"))
            aufgeraeumt(kopie)

            # Manipulierter signierter Installer in der Ablage → sha256_abweichung, keine Zieldatei, keine Löschung
            with open(installer, "ab") as fh:
                fh.write(b"x")
            p, kopie, aufrufe, ablage = ausfuehren()
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("sha256_abweichung", p.stderr)
            self.assertFalse(os.path.exists(ergebnis))
            self.assertFalse([a for a in ablage_anfragen(ablage) if a[0] == "DELETE"])
            aufgeraeumt(kopie)

            # Ablage serverseitig ohne Token → 503 beim Upload
            p, kopie, aufrufe, ablage = ausfuehren(server_token=None)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("503", p.stderr)
            aufgeraeumt(kopie)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_loeschschutz_mit_und_ohne_set_e(self):
        """G1/G2: Signierte oder fremde Artefakte werden nie gelöscht – weder nach PUT-409/Uploadfehler (auch in einer
        offenen bash ohne set -e) noch wenn nur gh run watch scheitert. Gelöscht wird nur ein eigener Upload ohne signed,
        dessen Lauf nachweislich (gh run view) fehlgeschlagen ist oder der nie gestartet wurde."""
        signiert, bericht = signiertes_ergebnis()
        tmp = tempfile.mkdtemp(prefix="Insight Loeschschutz ")
        try:
            quelle, q = lege_quelle(tmp)
            ziel = os.path.join(tmp, "Ausgang")
            installer = os.path.join(tmp, "signiert.bin")
            with open(installer, "wb") as fh:
                fh.write(signiert)
            basis = {"build_id": BID, "lauf": "4711", "installer": installer, "signieren": True,
                     "nachweise": {"4711": nachweis_dateien(bericht)}, "laeufe_folge": [[], [lauf(4711)]]}
            ablage_ordner = os.path.join(tmp, "Ablage")
            frueher_signiert = fake_signtool.signiere_bytes(tl.baue_installer(), {"kette": [], "zeitstempel": None})
            fremd_unsigned = tl.baue_installer(saat=99)
            fremd_quality = tl.quality_bytes(remote_e2e_fps=9.5)

            def ausfuehren(flags, vorbelegt=None, **aenderung):
                shutil.rmtree(ablage_ordner, ignore_errors=True)
                ablage = fake_storage.FakeAblage.einrichten(ablage_ordner, TOKEN_TEST)
                for kind, daten in (vorbelegt or {}).items():
                    ablage.roh_ablegen(BID, kind, daten)
                _e, _k, befehle = vb.vorbereiten(quelle, q, "2026.11.1", "pilot", None, True, ziel, REPO_BSP)
                env = self.umgebung(tmp, dict(basis, **aenderung))
                p = subprocess.run(["bash", *flags, "-c", befehle], capture_output=True, text=True, env=env, timeout=120)
                anfragen = [(a["methode"], a["pfad"].rsplit("/", 1)[-1], a["status"])
                            for a in ablage.protokoll() if a["quelle"] == "curl"]
                return p, anfragen, self.gh_aufrufe(tmp), ablage

            kein_start = {"unsigned_vorhanden_signed": dict(vorbelegt={"unsigned": tl.baue_installer(),
                                                                       "signed": frueher_signiert}),
                          "unsigned_fremd": dict(vorbelegt={"unsigned": fremd_unsigned}),
                          "quality_fremd": dict(vorbelegt={"quality": fremd_quality}),
                          "nur_signed_vorhanden": dict(vorbelegt={"signed": frueher_signiert})}
            nie_loeschen = {
                "watch_fehler_lauf_gruen": dict(watch_exit=1),
                "watch_abbruch_strg_c": dict(watch_exit=130),
                "watch_fehler_ausgang_unbekannt": dict(watch_exit=1, signieren=False, lauf_stand="fehler"),
                "watch_fehler_lauf_offen": dict(watch_exit=1, signieren=False,
                                                lauf_stand={"databaseId": 4711, "status": "waiting", "conclusion": None}),
                "watch_fehler_falscher_lauf": dict(watch_exit=1, signieren=False,
                                                   lauf_stand={"databaseId": 4700, "status": "completed",
                                                               "conclusion": "failure"}),
                "lauf_rot_aber_signed_abgelegt": dict(lauf_gruen=False, signieren=True),
                "lauf_unbestimmt": dict(laeufe_folge=[[], []], signieren=False),
            }
            for flags in (["-euo", "pipefail"], []):
                modus = " ".join(flags) or "ohne set -e"
                for name, fall in kein_start.items():
                    with self.subTest(modus=modus, fall=name):
                        vorher = {k: v for k, v in fall["vorbelegt"].items()}
                        p, anfragen, aufrufe, ablage = ausfuehren(flags, **fall)
                        self.assertNotEqual(p.returncode, 0, p.stderr)
                        self.assertFalse([a for a in anfragen if a[0] == "DELETE"], anfragen)
                        for kind, daten in vorher.items():
                            self.assertEqual(ablage.inhalt(BID, kind), daten, kind)
                        self.assertFalse([a for a in aufrufe if a[:2] == ["workflow", "run"]], "Start trotz Fehler")
                        self.assertFalse([a for a in aufrufe if a[:2] == ["run", "watch"]])
                for name, aenderung in nie_loeschen.items():
                    with self.subTest(modus=modus, fall=name):
                        p, anfragen, aufrufe, ablage = ausfuehren(flags, **aenderung)
                        self.assertNotEqual(p.returncode, 0, p.stderr)
                        self.assertFalse([a for a in anfragen if a[0] == "DELETE"], anfragen)
                        self.assertIsNotNone(ablage.inhalt(BID, "unsigned"))
                        if aenderung.get("signieren", True):
                            self.assertEqual(ablage.inhalt(BID, "signed"), signiert)
                        self.assertFalse([a for a in aufrufe if a[:2] == ["run", "download"]])
                        self.assertIn("nicht von Hand löschen", p.stderr)
                with self.subTest(modus=modus, fall="eigener_upload_lauf_rot"):
                    p, anfragen, aufrufe, ablage = ausfuehren(flags, lauf_gruen=False, signieren=False)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertEqual(anfragen[-1], ("DELETE", BID, 200))
                    self.assertIsNone(ablage.inhalt(BID, "unsigned"))
                with self.subTest(modus=modus, fall="eigener_upload_abgebrochen"):
                    p, anfragen, aufrufe, ablage = ausfuehren(flags, watch_exit=1, signieren=False, lauf_stand={
                        "databaseId": 4711, "status": "completed", "conclusion": "cancelled"})
                    self.assertNotEqual(p.returncode, 0)
                    self.assertEqual(anfragen[-1], ("DELETE", BID, 200))
                with self.subTest(modus=modus, fall="erfolg"):
                    ergebnis = os.path.join(ziel, "signiert-%s" % BID, sig.asset_name(BID))
                    if os.path.exists(ergebnis):
                        os.remove(ergebnis)
                    p, anfragen, aufrufe, ablage = ausfuehren(flags)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertTrue(os.path.exists(ergebnis))
                    self.assertFalse([a for a in anfragen if a[0] == "DELETE"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_loeschen_pruefen(self):
        sha, sha_q = "b" * 64, "c" * 64
        eigen = manifest(unsigned=(sha, 10), quality=(sha_q, 5))
        rot = {"databaseId": 4711, "status": "completed", "conclusion": "failure"}
        erlaubt = [(eigen, None, None), (manifest(unsigned=(sha, 10)), None, None)]
        erlaubt += [(eigen, "4711", dict(rot, conclusion=c)) for c in ("failure", "cancelled", "timed_out", "startup_failure")]
        for m, lauf_id, stand in erlaubt:
            with self.subTest(erlaubt=(lauf_id, stand)):
                self.assertIsNone(vb.loeschen_pruefen(m, BID, sha, sha_q, lauf_id, stand))
        mit_signed = manifest(unsigned=(sha, 10), quality=(sha_q, 5), signed=("e" * 64, 12))
        faelle = {
            "signiert_vorhanden": [(mit_signed, None, None), (mit_signed, "4711", rot),
                                   (manifest(unsigned=(sha, 10), signed=("e" * 64, 12)), None, None)],
            "fremder_upload": [(manifest(unsigned=("d" * 64, 10), quality=(sha_q, 5)), None, None),
                               (manifest(unsigned=(sha, 10), quality=("d" * 64, 5)), None, None)],
            "asset_fehlt": [(manifest(quality=(sha_q, 5)), None, None)],
            "manifest_ungueltig": [(None, None, None), (manifest(build_id="20261109-120001", unsigned=(sha, 10)), None, None)],
            "lauf_nicht_fehlgeschlagen": [(eigen, "4711", dict(rot, conclusion=c))
                                          for c in ("success", "neutral", "skipped", "action_required", None, "")],
            "lauf_offen": [(eigen, "4711", dict(rot, status=s, conclusion=None))
                           for s in ("queued", "in_progress", "waiting", "pending", "requested", None)],
            "lauf_unbekannt": [(eigen, "4711", None), (eigen, "4711", []), (eigen, "4711", dict(rot, databaseId=4700)),
                               (eigen, "4711", dict(rot, databaseId="4711x")), (eigen, None, rot)],
            "lauf_liste": [(eigen, "47; rm", rot)],
        }
        for code, varianten in faelle.items():
            for m, lauf_id, stand in varianten:
                with self.subTest(code=code, lauf=lauf_id, stand=stand):
                    self.assertEqual(code_von(vb.loeschen_pruefen, m, BID, sha, sha_q, lauf_id, stand), code)

    def test_curl_double_lehnt_token_als_argument_ab(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_storage.FakeAblage.einrichten(tmp, TOKEN_TEST)
            env = dict(os.environ, FAKE_STORAGE_ORDNER=tmp)
            skript = os.path.join(SIGNING, "fake_storage.py")
            p = subprocess.run([sys.executable, skript, "curl", "--proto", "=https", "-fsS", "-H",
                                "Authorization: Bearer " + TOKEN_TEST, BASIS + "/%s/manifest" % BID],
                               capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(p.returncode, 2)
            p = subprocess.run([sys.executable, skript, "curl", "-fsS", "-k", BASIS + "/%s/manifest" % BID],
                               capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(p.returncode, 2)

    def test_cli_unterbefehle(self):
        skript = os.path.join(SIGNING, "vorbereiten.py")

        def cli(*args, eingabe=""):
            return subprocess.run([sys.executable, skript, *args], input=eingabe, capture_output=True, text=True, timeout=60)

        p = cli("lauf-id", BID, "-", eingabe=json.dumps([lauf(5, build_id="20261109-120001"), lauf(4711)]))
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "4711"), p.stderr)
        p = cli("lauf-id", BID, "4700,4711", eingabe=json.dumps([lauf(4711), lauf(4700)]))
        self.assertEqual((p.returncode, p.stdout), (1, ""))
        self.assertIn("lauf_fehlt", p.stderr)
        p = cli("lauf-id", BID, "4700;rm", eingabe="[]")
        self.assertEqual((p.returncode, p.stdout), (1, ""))
        self.assertIn("lauf_liste", p.stderr)
        p = cli("lauf-id", BID, "-", eingabe="kein json")
        self.assertEqual(p.returncode, 1)
        self.assertIn("lauf_liste", p.stderr)
        p = cli("laeufe-vorher", BID, eingabe=json.dumps([lauf(4700), lauf(4690)]))
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "4690,4700"), p.stderr)
        p = cli("laeufe-vorher", BID, eingabe="[]")
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "-"), p.stderr)
        sha, sha_q = "b" * 64, "c" * 64
        p = cli("manifest-pruefen", BID, sha, sha_q, eingabe=json.dumps(manifest(unsigned=(sha, 10), quality=(sha_q, 5))))
        self.assertEqual(p.returncode, 0, p.stderr)
        p = cli("manifest-pruefen", BID, sha, sha_q, eingabe=json.dumps(manifest(unsigned=(sha, 10))))
        self.assertEqual(p.returncode, 1)
        self.assertIn("quality_fehlt", p.stderr)
        p = cli("manifest-pruefen", BID, sha, eingabe="{}")
        self.assertEqual((p.returncode, p.stdout), (2, ""))
        eigen = json.dumps(manifest(unsigned=(sha, 10), quality=(sha_q, 5)))
        rot = json.dumps({"databaseId": 4711, "status": "completed", "conclusion": "failure"})
        gruen = json.dumps({"databaseId": 4711, "status": "completed", "conclusion": "success"})
        p = cli("loeschen-pruefen", BID, sha, sha_q, "-", "-", eingabe=eigen)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = cli("loeschen-pruefen", BID, sha, sha_q, "4711", rot, eingabe=eigen)
        self.assertEqual(p.returncode, 0, p.stderr)
        for lauf_id, stand, eingabe, code in (("4711", gruen, eigen, "lauf_nicht_fehlgeschlagen"),
                                              ("4711", "kein json", eigen, "lauf_unbekannt"),
                                              ("4711", "-", eigen, "lauf_unbekannt"),
                                              ("-", "-", "", "manifest_ungueltig"),
                                              ("-", "-", json.dumps(manifest(unsigned=(sha, 10), signed=(sha, 9))),
                                               "signiert_vorhanden")):
            with self.subTest(code=code):
                p = cli("loeschen-pruefen", BID, sha, sha_q, lauf_id, stand, eingabe=eingabe)
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                self.assertIn("[%s]" % code, p.stderr)
                self.assertIn("nichts gelöscht", p.stderr)
        _s, bericht = signiertes_ergebnis()
        tmp = tempfile.mkdtemp(prefix="Insight CLI ")
        try:
            ordner = schreibe_nachweis(os.path.join(tmp, "nachweis"), nachweis_dateien(bericht))
            p = cli("nachweis-pruefen", ordner, REPO_BSP, "4711", BID, ERWARTUNG["sha256"], "2026.11.1", "pilot", "-")
            self.assertEqual(p.returncode, 0, p.stderr)
            p = cli("nachweis-pruefen", ordner, REPO_BSP, "4711", BID, ERWARTUNG["sha256"], "2026.11.1", "produktiv", "-")
            self.assertEqual(p.returncode, 1)
            self.assertIn("nachweis_abweichung", p.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def repo_dateien():
    """Alle Dateien des Arbeitsbaums (ohne .git und Caches) – das, was öffentlich würde."""
    for wurzel, ordner, dateien in os.walk(REPO):
        ordner[:] = [o for o in ordner if o == ".github" or not (o.startswith(".") or o == "__pycache__")]
        for d in dateien:
            if not d.endswith((".pyc",)):
                yield os.path.join(wurzel, d)


class RunbookUndOeffentlichkeit(unittest.TestCase):
    def test_runbook_pflichtinhalte(self):
        with open(DOKU, encoding="utf-8") as fh:
            doku = fh.read()
        pflicht = ["Artifact Signing Certificate Profile Signer", "Artifact Signing Identity Verifier",
                   "repo:insight-it-gmbh/cockpit-signing:environment:release-signing",
                   "repo:insight-it-gmbh@${OWNER_ID}/cockpit-signing@${REPO_ID}:environment:release-signing",
                   "https://token.actions.githubusercontent.com", "api://AzureADTokenExchange", "az role assignment list",
                   "actions/oidc/customization/sub", "http://timestamp.acs.microsoft.com", "https://weu.codesigning.azure.net",
                   "Erste Produktivprobe", "tools/signing/trockenlauf.py", "tools/signing/vorbereiten.py",
                   "tools/signing/workflow_check.py", "Prevent self-review", "Public Trust", "GitHub-Environment",
                   "Azure OIDC", "Pre-Release entfällt", "Key-Rotation entfällt", "7 Tage", "SIGNING_STORAGE_TOKEN",
                   "Repo-Secret", "https://cockpit.insight-it.de/api/signing/artifacts", "X-Artifact-SHA256", "replace=1",
                   "200 MiB", "remote_e2e_fps", "bestanden:true", "repository.private=false", "full_name",
                   "Pflicht-Reviewer funktionieren im öffentlichen Repository", "Kundenbinaries bleiben privat",
                   "nicht von Hand gelöscht", "Retention"]
        pflicht += list(wc.VARS)
        for text in pflicht:
            self.assertIn(text, doku)
        for text in ("signatur-nachweis-<BUILD_ID>", "unabhängig vom Ergebnis", "can_admins_bypass", "ArtifactSigning",
                     "NuGet", "umgebung_admin_bypass", "keine Sicherheitsgrenze", "job_workflow_ref",
                     "sign-cockpit.yml@refs/heads/main", "\"include_claim_keys\"", "nachweis-pruefen",
                     "nachweis_abweichung", "laeufe-vorher", "manifest-pruefen", "ergebnis-pruefen", ".unsigniert.exe",
                     "trap aufraeumen EXIT", "Schreibrecht", "-H @-", "gh secret set SIGNING_STORAGE_TOKEN"):
            self.assertTrue(text in doku, text)
        einrichtung = doku[doku.index("### 3. Azure OIDC"):doku.index("## Erste Produktivprobe")]
        self.assertIn("Schritt 0.1", einrichtung)
        produktivprobe = doku[doku.index("## Erste Produktivprobe"):doku.index("## Fehlerbilder")]
        self.assertNotIn("gh release", produktivprobe)
        self.assertNotIn("--testbuild", doku)
        self.assertNotIn("--limit 1", doku)
        for code in ("digest_abweichung", "build_id_abweichung", "signatur_fehlt", "selbstsigniert", "zeitstempel_fehlt",
                     "herausgeber_abweichung", "inhalt_geaendert", "upload_digest", "storage_token", "quality_ungueltig"):
            self.assertIn("`%s`" % code, doku)

    def test_abhaengigkeiten_der_signier_action_benannt(self):
        for pfad in (WORKFLOW, DOKU):
            with open(pfad, encoding="utf-8") as fh:
                text = fh.read()
            with self.subTest(pfad=os.path.basename(pfad)):
                self.assertFalse("kein nachinstallierter Drittcode" in text or "kein pip/Drittcode" in text)
                self.assertIn("ArtifactSigning", text)
                self.assertIn("NuGet", text)

    def test_readme_kurz_ohne_interna(self):
        with open(README, encoding="utf-8") as fh:
            readme = fh.read()
        self.assertLess(len(readme.splitlines()), 40)
        for verboten in ("Setup-Key", "setup_key", "Kunde ", "kunde.json", "NetBird", "Bearer", "TOKEN" + "=", "PASS" + "="):
            self.assertNotIn(verboten, readme)
        self.assertIn("keine Installer und keine Zugangsdaten", readme)

    def test_repository_ohne_secrets_interne_hosts_und_binaries(self):
        befunde = []
        for pfad in repo_dateien():
            rel = os.path.relpath(pfad, REPO)
            with open(pfad, "rb") as fh:
                roh = fh.read()
            if roh[:2] == b"MZ" or b"\0" in roh:
                befunde.append((rel, "binär"))
                continue
            text = roh.decode("utf-8")
            ausnahmen = [z for z in text.splitlines() if "scan-ausnahme: Testdaten" in z]
            if ausnahmen and rel != os.path.join("tools", "test_artifact_signing.py"):
                befunde.append((rel, "scan-ausnahme außerhalb der Tests"))
            text = "\n".join("" if "scan-ausnahme: Testdaten" in z else z for z in text.splitlines())
            for f in wc.scan_secrets(text):
                befunde.append((rel, f))
            for f in wc.scan_hosts(text, invalid_erlaubt=True):
                befunde.append((rel, f))
            for wort in ("gh" + "p_", "github" + "_pat_", "PRIVATE" + " KEY", "TOKEN" + "=", "PASS" + "="):
                if wort in text and rel != os.path.join("tools", "signing", "workflow_check.py"):
                    befunde.append((rel, wort))
        self.assertEqual(befunde, [])

    def test_scanner_finden_was_sie_sollen(self):
        self.assertTrue(wc.scan_secrets("x = 'gh" + "p_" + "a" * 36 + "'"))
        self.assertTrue(wc.scan_secrets("Authorization: Bearer " + "abcdef0123456789" * 2))
        self.assertTrue(wc.scan_secrets("SETUP_KEY=" + "A1B2C3D4E5F6G7H8"))
        self.assertTrue(wc.scan_secrets("export SIGNING_STORAGE_TOKEN" + "=abcdef0123456789"))
        self.assertEqual(wc.scan_secrets('token = env.get(TOKEN_ENV) or ""\nSECRET = "SIGNING_STORAGE_TOKEN"'), [])
        self.assertEqual(wc.scan_hosts("api://AzureADTokenExchange r\"https://[^/\\s]+/x\" https://cockpit.insight-it.de[:443]/"), [])
        self.assertTrue(wc.scan_secrets("-----BEGIN RSA PRIVATE" + " KEY-----"))
        self.assertEqual(wc.scan_secrets("printf 'Authorization: Bearer %s\\n' \"$X\""), [])
        self.assertEqual(wc.scan_secrets('"Bearer " + self._token'), [])
        hosts = wc.scan_hosts("https://intern.example.com/x 192.168.1.10 nb.firma.lan /home/nutzer/x")  # scan-ausnahme: Testdaten
        self.assertEqual({f["typ"] for f in hosts}, {"host", "ip", "interner Hostname", "lokaler Pfad"})
        self.assertEqual(wc.scan_hosts("https://cockpit.insight-it.de/api/signing/health 10.0.26100.4188"), [])


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=1).result
    if result.wasSuccessful():
        print(f"artifact_signing: {result.testsRun} Tests OK")
    sys.exit(0 if result.wasSuccessful() else 1)
