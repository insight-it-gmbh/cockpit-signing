#!/usr/bin/env python3
"""Statische Prüfung des Signatur-Workflows .github/workflows/sign-cockpit.yml (ohne Fremdbibliotheken).

1. Strenger YAML-Teilmengen-Parser: Block-Mappings und -Listen, einfache/gequotete Skalare, Literalblöcke (| und |-).
   Abgelehnt werden alles andere (Anker, Aliasse, Tags, Flow-Stil, Tabs, doppelte Schlüssel, Mehrfachdokumente,
   mehrzeilige einfache Skalare) – lieber ein klarer Fehler als eine stille Fehldeutung.
2. Schema: erlaubte Schlüssel je Ebene, nur workflow_dispatch mit festen Eingaben, Rechte je Job, Environment nur im
   Signier-Job, needs-Graph, Runner, Zeitlimits, Schrittform.
3. Action-Pins: Commit-SHA und Tag-Kommentar des geprüften Stands; with-Schlüssel gegen die Eingaben der action.yml
   genau dieses Commits (Abzug vom 09.11.2026), Pflichteingaben vorhanden.
4. Signaturpfad: feste Schrittfolge, Helfer-Aufrufe ohne Argumente (Werte nur über env), keine ${{ }} in run-Blöcken,
   erlaubte Ausdrücke und Schrittverweise, kein Actions-Cache für die Signier-Werkzeugkette, Upload erst nach
   Nachprüfung und Ablage-Prüfung.
5. Transport nur über die private Ablage: einziges Secret ist SIGNING_STORAGE_TOKEN, und zwar nur im env der
   Ablage-Schritte (eigene Helfer), nie in Actions, Job-env oder run-Text; kein Release, kein gh release, kein
   Installer als GitHub-Artefakt (einziges Artefakt: die JSON-Nachweise).
6. Secret-Scan und Host-Prüfung: nur freigegebene öffentliche Hosts, keine IP-Literale, keine lokalen Pfade.

Aufruf: python3 tools/signing/workflow_check.py [pfad]   → Befunde, Exit 0 nur ohne Befund
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
REPO = os.path.dirname(TOOLS)
sys.path.insert(0, HERE)

import artifact_signing as sig  # noqa: E402

WORKFLOW = os.path.join(REPO, ".github", "workflows", "sign-cockpit.yml")

# ---------------------------------------------------------------- Action-Abzug (action.yml am gepinnten Commit)
ACTIONS = {
    "actions/checkout": {
        "sha": "3d3c42e5aac5ba805825da76410c181273ba90b1", "tag": "v7.0.1", "pflicht": (),
        "eingaben": ("allow-unsafe-pr-checkout", "clean", "fetch-depth", "fetch-tags", "filter", "github-server-url",
                     "lfs", "path", "persist-credentials", "ref", "repository", "set-safe-directory", "show-progress",
                     "sparse-checkout", "sparse-checkout-cone-mode", "ssh-key", "ssh-known-hosts", "ssh-strict",
                     "ssh-user", "submodules", "token"),
        "ausgaben": ("commit", "ref")},
    "azure/login": {
        "sha": "a641126d1b8aa4d1fa005f4f92df94a3a4c4c906", "tag": "v3.1.0", "pflicht": (),
        "eingaben": ("allow-no-subscriptions", "audience", "auth-type", "client-id", "creds", "enable-AzPSSession",
                     "environment", "mask-client-id", "max-context-population", "subscription-id", "tenant-id"),
        "ausgaben": ()},
    "azure/artifact-signing-action": {
        "sha": "c7ab2a863ab5f9a846ddb8265964877ef296ee82", "tag": "v2.0.0", "pflicht": ("certificate-profile-name", "endpoint"),
        "eingaben": ("append-signature", "azure-client-certificate-path", "azure-client-id", "azure-client-secret",
                     "azure-client-send-certificate-chain", "azure-password", "azure-tenant-id", "azure-username",
                     "batch-size", "cache-dependencies", "certificate-profile-name", "clickonce-application-name",
                     "clickonce-publisher-name", "correlation-id", "description", "description-url", "endpoint",
                     "enhanced-key-usage", "exclude-azure-cli-credential", "exclude-azure-developer-cli-credential",
                     "exclude-azure-powershell-credential", "exclude-environment-credential",
                     "exclude-interactive-browser-credential", "exclude-managed-identity-credential",
                     "exclude-shared-token-cache-credential", "exclude-visual-studio-code-credential",
                     "exclude-visual-studio-credential", "exclude-workload-identity-credential", "file-digest", "files",
                     "files-catalog", "files-folder", "files-folder-depth", "files-folder-filter", "files-folder-recurse",
                     "generate-digest-path", "generate-digest-xml", "generate-page-hashes", "generate-pkcs7",
                     "ingest-digest-path", "pkcs7-oid", "pkcs7-options", "sign-digest", "signing-account-name",
                     "suppress-page-hashes", "timeout", "timestamp-digest", "timestamp-rfc3161", "trace",
                     "trusted-signing-account-name"),
        "ausgaben": ()},
    "actions/upload-artifact": {
        "sha": "cf430e030ddbb5b0abf93d22962f4752f3646cd9", "tag": "v7.0.2", "pflicht": ("path",),
        "eingaben": ("archive", "compression-level", "if-no-files-found", "include-hidden-files", "name", "overwrite",
                     "path", "retention-days"),
        "ausgaben": ("artifact-digest", "artifact-id", "artifact-url")},
}

# ---------------------------------------------------------------- Soll-Form des Workflows
EINGABEN = {"build_id": ("string", True, None), "sha256": ("string", True, None),
            "quality_sha256": ("string", True, None), "version": ("string", True, None),
            "kanal": ("choice", True, ["intern", "pilot", "produktiv"]), "vorgaenger_id": ("string", False, None),
            "erstausrollung": ("boolean", False, None)}
VARS = ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "ARTIFACT_SIGNING_ENDPOINT",
        "ARTIFACT_SIGNING_ACCOUNT", "ARTIFACT_SIGNING_PROFILE", "ARTIFACT_SIGNING_PUBLISHER")
SECRET = "SIGNING_STORAGE_TOKEN"
SECRET_AUSDRUCK = "${{ secrets.%s }}" % SECRET
SIGN_ENV = {"SIGN_BUILD_ID": "${{ inputs.build_id }}", "SIGN_SHA256": "${{ inputs.sha256 }}",
            "SIGN_QUALITY_SHA256": "${{ inputs.quality_sha256 }}",
            "SIGN_VERSION": "${{ inputs.version }}", "SIGN_KANAL": "${{ inputs.kanal }}",
            "SIGN_VORGAENGER_ID": "${{ inputs.vorgaenger_id }}", "SIGN_ERSTAUSROLLUNG": "${{ inputs.erstausrollung }}"}
UMGEBUNG = "release-signing"
JOBS = {"tests": {"runs-on": "ubuntu-24.04", "permissions": {"contents": "read"}},
        "vorpruefung": {"runs-on": "ubuntu-24.04", "permissions": {"actions": "read", "contents": "read"}},
        "signieren": {"runs-on": "windows-2025", "permissions": {"contents": "read", "id-token": "write"}}}
CHECKOUT_WITH = {"persist-credentials": False}
LOGIN_WITH = {"client-id": "${{ vars.AZURE_CLIENT_ID }}", "tenant-id": "${{ vars.AZURE_TENANT_ID }}",
              "subscription-id": "${{ vars.AZURE_SUBSCRIPTION_ID }}"}
SIGNIER_WITH = {
    "endpoint": "${{ vars.ARTIFACT_SIGNING_ENDPOINT }}", "signing-account-name": "${{ vars.ARTIFACT_SIGNING_ACCOUNT }}",
    "certificate-profile-name": "${{ vars.ARTIFACT_SIGNING_PROFILE }}", "files": "${{ steps.vorpruefen.outputs.datei }}",
    "file-digest": "SHA256", "timestamp-rfc3161": "http://timestamp.acs.microsoft.com", "timestamp-digest": "SHA256",
    "description": sig.SIGNATUR_BESCHREIBUNG, "cache-dependencies": "false",
    "exclude-environment-credential": True, "exclude-workload-identity-credential": True,
    "exclude-managed-identity-credential": True, "exclude-shared-token-cache-credential": True,
    "exclude-visual-studio-credential": True, "exclude-visual-studio-code-credential": True,
    "exclude-azure-cli-credential": False, "exclude-azure-powershell-credential": True,
    "exclude-azure-developer-cli-credential": True, "exclude-interactive-browser-credential": True}
UPLOAD_NACHWEIS_WITH = {"name": "signatur-nachweis-${{ inputs.build_id }}",
                        "path": "${{ steps.nachpruefen.outputs.nachweis_ordner }}", "if-no-files-found": "error",
                        "retention-days": 30}
# Feste Schrittfolge der Jobs: (id, Art, Detail)
ABLAUF = {
    "tests": [(None, "checkout", None), (None, "run", "python3 tools/test_artifact_signing.py"),
              (None, "run", "python3 tools/signing/workflow_check.py")],
    "vorpruefung": [(None, "checkout", None), ("eingaben", "helfer", "eingaben"), ("umgebung", "helfer", "umgebung"),
                    ("qualitaet", "helfer", "qualitaet"), ("laden", "helfer", "laden"),
                    ("vorpruefen", "helfer", "vorpruefen")],
    "signieren": [(None, "checkout", None), ("eingaben", "helfer", "eingaben"), ("qualitaet", "helfer", "qualitaet"),
                  ("laden", "helfer", "laden"), ("vorpruefen", "helfer", "vorpruefen"),
                  ("azure_login", "action", "azure/login"), ("signieren", "action", "azure/artifact-signing-action"),
                  ("abmelden", "abmelden", None), ("nachpruefen", "helfer", "nachpruefen"),
                  ("hochladen", "helfer", "hochladen"), ("ablage_pruefen", "helfer", "ablage-pruefen"),
                  ("upload_nachweis", "action", "actions/upload-artifact")],
}
ABLAGE_ENV = {SECRET: SECRET_AUSDRUCK}
ABLAGE_SCHRITTE = {("vorpruefung", "qualitaet"), ("vorpruefung", "laden"), ("signieren", "qualitaet"),
                   ("signieren", "laden"), ("signieren", "hochladen"), ("signieren", "ablage_pruefen")}
SCHRITT_ENV = {("vorpruefung", "umgebung"): {"GH_TOKEN": "${{ github.token }}"},
               ("signieren", "nachpruefen"): {"SIGN_HERAUSGEBER": "${{ vars.ARTIFACT_SIGNING_PUBLISHER }}"}}
SCHRITT_ENV.update({s: ABLAGE_ENV for s in ABLAGE_SCHRITTE})
WITH_SOLL = {("signieren", "azure_login"): LOGIN_WITH, ("signieren", "signieren"): SIGNIER_WITH,
             ("signieren", "upload_nachweis"): UPLOAD_NACHWEIS_WITH}
SHELL = {"tests": "bash", "vorpruefung": "bash", "signieren": "pwsh"}
PYTHON = {"tests": "python3", "vorpruefung": "python3", "signieren": "python"}
ERLAUBTE_BEDINGUNGEN = {("signieren", "abmelden"): "always()"}
OBERSCHLUESSEL = ("name", "run-name", "on", "permissions", "concurrency", "jobs")
JOBSCHLUESSEL = ("name", "needs", "runs-on", "environment", "permissions", "timeout-minutes", "env", "steps")
SCHRITTSCHLUESSEL = ("id", "name", "uses", "run", "shell", "with", "env", "if")
VERBOTEN = (("gh release", "release_verboten", "gh release (Installer gehören nie in GitHub-Releases)"),
            ("releases/", "release_verboten", "Release-API (Installer gehören nie in GitHub-Releases)"),
            ("prerelease", "release_verboten", "Pre-Release (Transport nur über die Ablage)"),
            ("archive: false", "installer_artefakt", "Rohdatei-Artefakt (Installer nie als GitHub-Artefakt)"),
            ("outputs.installer", "installer_artefakt", "Installer-Pfad in einem Action-Schritt"))
AUSDRUCK_MUSTER = (re.compile(r"inputs\.(%s)" % "|".join(EINGABEN)), re.compile(r"vars\.(%s)" % "|".join(VARS)),
                   re.compile(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)"), re.compile(r"github\.token"),
                   re.compile(r"secrets\.%s" % SECRET))

# ---------------------------------------------------------------- Secret- und Host-Prüfung (auch für Doku/Tests)
ERLAUBTE_HOSTS = ("cockpit.insight-it.de", "timestamp.acs.microsoft.com", "token.actions.githubusercontent.com",
                  "weu.codesigning.azure.net", "neu.codesigning.azure.net", "github.com", "docs.github.com")
SECRET_MUSTER = (("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
                 ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
                 ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
                 ("bearer_wert", re.compile(r"Bearer\s+(?![<$%{\"'])[A-Za-z0-9._~+/=-]{20,}")),
                 ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
                 ("azure_geheimnis", re.compile(r"(?i)client[_-]?secret\s*[:=]\s*[\"']?[A-Za-z0-9~._-]{20,}")),
                 ("zuweisung", re.compile(r"\b(?:[A-Z0-9]+_)*(?:TOKEN|PASS|PASSWORD|PASSWORT|SECRET|SETUP_KEY)=[\"']?"
                                          r"(?![\"'$<{(%]|\s|$)[^\s\"']{8,}")),
                 ("setup_key", re.compile(r"\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b")))
IPV4_RE = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])")
URL_HOST_RE = re.compile(r"\b(?:https?|ftps?|sftp|ssh|wss?|git)://([^/\s\"'`<>)\]|]+)", re.I)
INTERN_MUSTER = ((re.compile(r"(?i)\b[a-z0-9-]+\.(?:lan|local|internal|intra|corp|home\.arpa)\b"), "interner Hostname"),
                 (re.compile(r"(?i)(?:^|[\s\"'`(=])(?:/home/|/root/|/opt/|/srv/|[A-Z]:\\\\Users\\\\)"), "lokaler Pfad"))


def scan_secrets(text):
    """Mögliche Klartext-Geheimnisse (Muster, keine Entropie-Heuristik). Liefert [{typ, zeile}]."""
    funde = []
    for nr, zeile in enumerate(text.splitlines(), start=1):
        for typ, muster in SECRET_MUSTER:
            if muster.search(zeile):
                funde.append({"typ": typ, "zeile": nr})
    return funde


def scan_hosts(text, erlaubt=ERLAUBTE_HOSTS, invalid_erlaubt=False):
    """Hosts in URLs nur aus der Freigabeliste (oder *.invalid für Testdaten), keine IPv4-Literale, keine internen
    Namen oder lokalen Pfade. Liefert [{typ, wert, zeile}]."""
    funde = []
    for nr, zeile in enumerate(text.splitlines(), start=1):
        for m in URL_HOST_RE.finditer(zeile):
            roh = m.group(1).rsplit("@", 1)[-1].lower()
            host = (re.match(r"[a-z0-9.-]*", roh).group(0)).strip(".-")
            if "." not in host or roh[len(host):len(host) + 1] in ("$", "{", "%", "\\"):
                continue                                    # Platzhalter oder regulärer Ausdruck
            if host in erlaubt or (invalid_erlaubt and host.endswith(".invalid")):
                continue
            funde.append({"typ": "host", "wert": host, "zeile": nr})
        for m in IPV4_RE.finditer(zeile):
            funde.append({"typ": "ip", "wert": m.group(0), "zeile": nr})
        for muster, typ in INTERN_MUSTER:
            m = muster.search(zeile)
            if m and not m.group(0).lower().endswith(".invalid"):
                funde.append({"typ": typ, "wert": m.group(0).strip(), "zeile": nr})
    return funde


# ---------------------------------------------------------------- YAML-Teilmenge

class YamlFehler(ValueError):
    pass


_SCHLUESSEL = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*):(?:[ ]+(.*))?$")
_INDIKATOR = tuple("[]{},&*!|>%@`?") + ("- ", "-\n")


def _ohne_kommentar(rest, nr):
    rest = rest.strip()
    if not rest or rest.startswith("#"):
        return ""
    if rest[0] in "\"'":
        q, i = rest[0], 1
        while i < len(rest):
            if q == "'" and rest[i] == "'" and rest[i + 1:i + 2] == "'":
                i += 2
                continue
            if q == '"' and rest[i] == "\\":
                i += 2
                continue
            if rest[i] == q:
                break
            i += 1
        else:
            raise YamlFehler("Zeile %d: Anführungszeichen nicht geschlossen" % nr)
        nachher = rest[i + 1:]
        if nachher.strip() and not re.match(r"^\s+#", nachher):
            raise YamlFehler("Zeile %d: Text nach geschlossenem Skalar" % nr)
        return rest[:i + 1]
    m = re.search(r"\s#", rest)
    return (rest[:m.start()] if m else rest).rstrip()


def _skalar(tok, nr):
    if tok.startswith('"'):
        try:
            return json.loads(tok)
        except ValueError:
            raise YamlFehler("Zeile %d: doppelt gequoteter Skalar nicht unterstützt" % nr) from None
    if tok.startswith("'"):
        return tok[1:-1].replace("''", "'")
    if tok.startswith(_INDIKATOR) or tok == "-":
        raise YamlFehler("Zeile %d: nicht unterstützte YAML-Form %r" % (nr, tok[:20]))
    if ": " in tok or tok.endswith(":"):
        raise YamlFehler("Zeile %d: Doppelpunkt mit Leerzeichen im Skalar (bitte quoten)" % nr)
    if tok in ("true", "false"):
        return tok == "true"
    if tok in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?[0-9]+", tok):
        return int(tok)
    return tok


class _Parser:
    def __init__(self, text):
        if "\t" in text:
            raise YamlFehler("Tabulatoren sind nicht erlaubt")
        if "\r" in text.replace("\r\n", ""):
            raise YamlFehler("Einzelne Wagenrückläufe sind nicht erlaubt")
        self.zeilen = text.replace("\r\n", "\n").split("\n")
        self.i = 0

    def _naechste(self):
        while self.i < len(self.zeilen):
            s = self.zeilen[self.i].strip()
            if s and not s.startswith("#"):
                if s in ("---", "...") or s.startswith("%"):
                    raise YamlFehler("Zeile %d: Dokumentmarker/Direktiven nicht erlaubt" % (self.i + 1))
                zeile = self.zeilen[self.i]
                return len(zeile) - len(zeile.lstrip(" ")), zeile.lstrip(" ")
            self.i += 1
        return None

    def dokument(self):
        n = self._naechste()
        if n is None:
            raise YamlFehler("Leeres Dokument")
        if n[0] != 0:
            raise YamlFehler("Zeile %d: Dokument muss ohne Einrückung beginnen" % (self.i + 1))
        wert = self._knoten(0)
        if self._naechste() is not None:
            raise YamlFehler("Zeile %d: unerwarteter Inhalt" % (self.i + 1))
        return wert

    def _knoten(self, einzug):
        _, inhalt = self._naechste()
        return self._liste(einzug) if inhalt == "-" or inhalt.startswith("- ") else self._mapping(einzug)

    def _mapping(self, einzug):
        erg = {}
        while True:
            n = self._naechste()
            if n is None or n[0] < einzug:
                return erg
            nr = self.i + 1
            if n[0] > einzug:
                raise YamlFehler("Zeile %d: unerwartete Einrückung" % nr)
            m = _SCHLUESSEL.match(n[1])
            if not m:
                raise YamlFehler("Zeile %d: erwartet „schlüssel: wert“" % nr)
            if m.group(1) in erg:
                raise YamlFehler("Zeile %d: doppelter Schlüssel %r" % (nr, m.group(1)))
            self.i += 1
            erg[m.group(1)] = self._wert(_ohne_kommentar(m.group(2) or "", nr), einzug, nr)

    def _wert(self, tok, einzug, nr):
        if tok in ("|", "|-"):
            return self._block(einzug, tok)
        if tok:
            return _skalar(tok, nr)
        n = self._naechste()
        if n is not None and n[0] > einzug:
            return self._knoten(n[0])
        if n is not None and n[0] == einzug and (n[1] == "-" or n[1].startswith("- ")):
            raise YamlFehler("Zeile %d: Listen bitte eingerückt unter den Schlüssel schreiben" % (self.i + 1))
        return None

    def _liste(self, einzug):
        erg = []
        while True:
            n = self._naechste()
            if n is None or n[0] < einzug:
                return erg
            nr = self.i + 1
            if n[0] > einzug or not (n[1] == "-" or n[1].startswith("- ")):
                raise YamlFehler("Zeile %d: Listeneintrag erwartet" % nr)
            if n[1] == "-":
                self.i += 1
                naechste = self._naechste()
                erg.append(self._knoten(naechste[0]) if naechste and naechste[0] > einzug else None)
                continue
            rest = n[1][2:]
            innen = einzug + 2 + len(rest) - len(rest.lstrip(" "))
            rest = rest.lstrip(" ")
            if _SCHLUESSEL.match(rest):
                self.zeilen[self.i] = " " * innen + rest
                erg.append(self._mapping(innen))
            elif _ohne_kommentar(rest, nr) in ("|", "|-"):
                self.i += 1
                erg.append(self._block(einzug, _ohne_kommentar(rest, nr)))
            else:
                self.i += 1
                erg.append(_skalar(_ohne_kommentar(rest, nr), nr))

    def _block(self, einzug, art):
        zeilen, block = [], None
        while self.i < len(self.zeilen):
            zeile = self.zeilen[self.i]
            if not zeile.strip():
                zeilen.append("")
                self.i += 1
                continue
            aktuell = len(zeile) - len(zeile.lstrip(" "))
            if aktuell <= einzug:
                break
            block = aktuell if block is None else block
            if aktuell < block:
                raise YamlFehler("Zeile %d: Literalblock uneinheitlich eingerückt" % (self.i + 1))
            zeilen.append(zeile[block:])
            self.i += 1
        while zeilen and not zeilen[-1]:
            zeilen.pop()
        text = "\n".join(zeilen)
        return text + "\n" if art == "|" and text else text


def parse_yaml(text):
    return _Parser(text).dokument()



# ---------------------------------------------------------------- Prüfung

def _ausdruecke(wert):
    if isinstance(wert, str):
        return re.findall(r"\$\{\{(.*?)\}\}", wert)
    if isinstance(wert, dict):
        return [a for v in wert.values() for a in _ausdruecke(v)]
    if isinstance(wert, list):
        return [a for v in wert for a in _ausdruecke(v)]
    return []


def _helfer(run, job):
    m = re.fullmatch(r"(python3?) tools/signing/artifact_signing\.py ([a-z-]+)\n?", run or "")
    return m.group(2) if m and m.group(1) == PYTHON[job] and m.group(2) in sig.BEFEHLE else None


def _art(schritt, job):
    if "uses" in schritt:
        ref = str(schritt["uses"])
        name = ref.split("@", 1)[0].lower()
        return ("checkout", None) if name == "actions/checkout" else ("action", name)
    run = schritt.get("run")
    if isinstance(run, str) and run.strip() == "az account clear":
        return "abmelden", None
    befehl = _helfer(run, job)
    return ("helfer", befehl) if befehl else ("run", run.strip() if isinstance(run, str) else None)


def pruefe_workflow(text):
    befunde = []

    def fehler(code, meldung):
        befunde.append({"code": code, "meldung": meldung})

    try:
        wf = parse_yaml(text)
    except YamlFehler as exc:
        fehler("yaml", str(exc))
        return befunde
    if not isinstance(wf, dict):
        fehler("schema_pflicht", "Workflow ist kein Mapping")
        return befunde
    _rohtext(text, fehler)
    for k in wf:
        if k not in OBERSCHLUESSEL:
            fehler("schema_schluessel", "Unerwarteter Schlüssel auf oberster Ebene: %s" % k)
    for k in ("name", "on", "permissions", "jobs"):
        if k not in wf:
            fehler("schema_pflicht", "Pflichtschlüssel fehlt: %s" % k)
    _trigger(wf.get("on"), fehler)
    if wf.get("permissions") != {"contents": "read"}:
        fehler("rechte", "Workflow-Rechte müssen genau contents: read sein")
    konk = wf.get("concurrency")
    if not (isinstance(konk, dict) and set(konk) == {"group", "cancel-in-progress"} and isinstance(konk["group"], str)
            and konk["cancel-in-progress"] is False):
        fehler("concurrency", "concurrency mit fester Gruppe und cancel-in-progress: false fehlt")
    for ausdruck in _ausdruecke({k: v for k, v in wf.items() if k != "jobs"}):
        _ausdruck_erlaubt(ausdruck, None, {}, fehler, nur_inputs=True)
    jobs = wf.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != set(JOBS):
        fehler("jobs", "Jobs müssen genau %s sein" % ", ".join(JOBS))
        return befunde
    for name, job in jobs.items():
        _job(name, job, fehler)
    return befunde


def _rohtext(text, fehler):
    for m in re.finditer(r"\bsecrets\.([A-Za-z0-9_]*)", text):
        if m.group(1) != SECRET:
            fehler("secret_referenz", "secrets.%s im Workflow – erlaubt ist nur secrets.%s" % (m.group(1), SECRET))
    if text.count("secrets." + SECRET) != len(ABLAGE_SCHRITTE):
        fehler("secret_referenz", "secrets.%s muss genau in den %d Ablage-Schritten stehen" % (SECRET, len(ABLAGE_SCHRITTE)))
    unten = text.lower()
    for muster, code, was in VERBOTEN:
        if muster in unten:
            fehler(code, "Verboten im Workflow: %s" % was)
    for f in scan_hosts(text):
        fehler("intern", "Nicht freigegebener Host/Adresse/Pfad im Workflow (Zeile %d): %s" % (f["zeile"], f["wert"]))
    for f in scan_secrets(text):
        fehler("klartext_secret", "Möglicher Klartext-Secret (%s) in Zeile %d" % (f["typ"], f["zeile"]))
    for nr, zeile in enumerate(text.splitlines(), start=1):
        m = re.match(r"^\s*(?:-\s+)?uses:\s*(\S+)(?:\s+#\s*(\S+))?\s*$", zeile)
        if not m and re.match(r"^\s*(?:-\s+)?uses:", zeile):
            fehler("pin", "Zeile %d: uses-Zeile nicht auswertbar" % nr)
            continue
        if not m:
            continue
        ref, kommentar = m.group(1), m.group(2)
        am = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})", ref)
        if not am:
            fehler("pin", "Zeile %d: Action nicht per Commit-SHA gepinnt: %s" % (nr, ref))
            continue
        stand = ACTIONS.get(am.group(1).lower())
        if not stand:
            fehler("pin", "Zeile %d: Action nicht im geprüften Abzug: %s" % (nr, am.group(1)))
        elif stand["sha"] != am.group(2):
            fehler("pin", "Zeile %d: SHA weicht vom geprüften Stand %s ab" % (nr, stand["tag"]))
        elif kommentar != stand["tag"]:
            fehler("pin_kommentar", "Zeile %d: Tag-Kommentar muss # %s sein" % (nr, stand["tag"]))


def _trigger(on, fehler):
    if not (isinstance(on, dict) and list(on) == ["workflow_dispatch"] and isinstance(on["workflow_dispatch"], dict)
            and list(on["workflow_dispatch"]) == ["inputs"]):
        fehler("trigger", "Nur workflow_dispatch mit inputs ist erlaubt (kein push, kein pull_request, kein Zeitplan)")
        return
    eingaben = on["workflow_dispatch"]["inputs"]
    if not isinstance(eingaben, dict) or set(eingaben) != set(EINGABEN):
        fehler("eingaben", "Eingaben müssen genau %s sein" % ", ".join(EINGABEN))
        return
    for name, (typ, pflicht, optionen) in EINGABEN.items():
        e = eingaben[name]
        if not isinstance(e, dict) or set(e) - {"description", "required", "type", "default", "options"}:
            fehler("eingaben", "Eingabe %s: unerwartete Felder" % name)
            continue
        if e.get("type") != typ or e.get("required") is not pflicht or not str(e.get("description") or "").strip():
            fehler("eingaben", "Eingabe %s muss type %s, required %s und eine Beschreibung haben" % (name, typ, pflicht))
        if optionen is not None and e.get("options") != optionen:
            fehler("eingaben", "Eingabe %s: Optionen müssen %s sein" % (name, optionen))


def _ausdruck_erlaubt(ausdruck, job, frueher, fehler, nur_inputs=False, secret_ok=False):
    a = ausdruck.strip()
    muster = AUSDRUCK_MUSTER[:1] if nur_inputs else AUSDRUCK_MUSTER
    treffer = next((m.fullmatch(a) for m in muster if m.fullmatch(a)), None)
    if not treffer:
        fehler("ausdruck", "Ausdruck nicht erlaubt: ${{ %s }}%s" % (a, " (Job %s)" % job if job else ""))
        return
    if a.startswith("secrets.") and not secret_ok:
        fehler("secret_ort", "secrets.%s nur im env der Ablage-Schritte%s" % (SECRET, " (Job %s)" % job if job else ""))
    if a.startswith("steps."):
        sid, ausgabe = treffer.group(1), treffer.group(2)
        if sid not in frueher:
            fehler("ausdruck_ref", "Job %s: Verweis auf späteren oder unbekannten Schritt %s" % (job, sid))
        elif ausgabe not in frueher[sid]:
            fehler("ausdruck_ref", "Job %s: Schritt %s hat keine Ausgabe %s" % (job, sid, ausgabe))


def _job(name, job, fehler):
    if not isinstance(job, dict):
        fehler("schema_pflicht", "Job %s ist kein Mapping" % name)
        return
    for k in job:
        if k not in JOBSCHLUESSEL:
            fehler("schema_schluessel", "Job %s: unerwarteter Schlüssel %s" % (name, k))
    soll = JOBS[name]
    if job.get("runs-on") != soll["runs-on"]:
        fehler("runner", "Job %s muss auf %s laufen" % (name, soll["runs-on"]))
    if not isinstance(job.get("timeout-minutes"), int) or not 1 <= job["timeout-minutes"] <= 60:
        fehler("timeout", "Job %s braucht timeout-minutes zwischen 1 und 60" % name)
    if job.get("permissions") != soll["permissions"]:
        fehler("rechte", "Job %s: Rechte müssen genau %s sein" % (name, soll["permissions"]))
    if (job.get("environment") == UMGEBUNG) != (name == "signieren") or ("environment" in job and name != "signieren"):
        fehler("umgebung", "Environment %s gehört genau an den Job signieren" % UMGEBUNG)
    needs = job.get("needs")
    if name == "signieren":
        if not isinstance(needs, list) or sorted(needs) != ["tests", "vorpruefung"]:
            fehler("needs", "signieren muss auf tests und vorpruefung warten")
    elif needs is not None:
        fehler("needs", "Job %s darf keine Abhängigkeiten haben" % name)
    if name == "tests":
        if "env" in job:
            fehler("eingaben_env", "Job tests braucht keine Signatur-Eingaben")
    elif job.get("env") != SIGN_ENV:
        fehler("eingaben_env", "Job %s: env muss genau die SIGN_*-Eingaben aus inputs enthalten" % name)
    for ausdruck in _ausdruecke(job.get("env") or {}):
        _ausdruck_erlaubt(ausdruck, name, {}, fehler)
    schritte = job.get("steps")
    if not isinstance(schritte, list) or not schritte:
        fehler("schema_pflicht", "Job %s ohne Schritte" % name)
        return
    _schritte(name, schritte, fehler)


def _schritte(job, schritte, fehler):
    frueher, ids, arten = {}, [], []
    for nr, s in enumerate(schritte, start=1):
        ort = "Job %s, Schritt %d" % (job, nr)
        if not isinstance(s, dict):
            fehler("schritt_form", "%s ist kein Mapping" % ort)
            continue
        for k in s:
            if k not in SCHRITTSCHLUESSEL:
                fehler("schema_schluessel", "%s: unerwarteter Schlüssel %s" % (ort, k))
        if ("uses" in s) == ("run" in s):
            fehler("schritt_form", "%s: genau eins von uses/run" % ort)
        if not str(s.get("name") or "").strip():
            fehler("schritt_name", "%s ohne Namen" % ort)
        sid = s.get("id")
        if sid is not None and (sid in ids or not re.fullmatch(r"[a-z][a-z0-9_]*", str(sid))):
            fehler("schritt_id", "%s: Schritt-ID %r doppelt oder ungültig" % (ort, sid))
        ids.append(sid)
        bedingung = s.get("if")
        erlaubt = ERLAUBTE_BEDINGUNGEN.get((job, sid if sid else s.get("name")))
        if bedingung is not None and bedingung != erlaubt:
            fehler("bedingung", "%s: Bedingung %r nicht erlaubt (Abbruch darf nie übersprungen werden)" % (ort, bedingung))
        if erlaubt and bedingung != erlaubt:
            fehler("bedingung", "%s: muss %s tragen" % (ort, erlaubt))
        art = _art(s, job)
        arten.append((sid, art[0], art[1]))
        env = s.get("env") or {}
        for k in ("SIGN_GH", "SIGN_SIGNTOOL", "SIGN_TROCKENLAUF", "SIGN_STORAGE_FAKE", "SIGN_GITHUB_SIMULATION",
                  "RUNNER_ENVIRONMENT", "GITHUB_ACTIONS", "GITHUB_EVENT_PATH"):
            if k in env:
                fehler("ueberschreibung", "%s: %s gehört nie in den Workflow" % (ort, k))
        if any(k.startswith("FAKE_") for k in env):
            fehler("ueberschreibung", "%s: Trockenlauf-Variablen gehören nie in den Workflow" % ort)
        if "run" in s:
            run = s["run"]
            if not isinstance(run, str) or "${{" in run:
                fehler("ausdruck_in_run", "%s: keine ${{ }}-Ausdrücke in run (Eingaben nur über env)" % ort)
            if s.get("shell") != SHELL[job]:
                fehler("shell", "%s: shell muss %s sein" % (ort, SHELL[job]))
            if "with" in s:
                fehler("schritt_form", "%s: with nur bei uses" % ort)
            if isinstance(run, str) and re.search(r"\bpip\b", run):
                fehler("pip", "%s: kein pip in diesem Workflow (Helfer und Tests nur Standardbibliothek)" % ort)
        if "uses" in s:
            _uses(job, ort, s, fehler)
        secret_ok = (job, sid) in ABLAGE_SCHRITTE and art[0] == "helfer"
        for ausdruck in _ausdruecke(env):
            _ausdruck_erlaubt(ausdruck, job, frueher, fehler, secret_ok=secret_ok)
        for ausdruck in _ausdruecke({k: v for k, v in s.items() if k not in ("run", "env")}):
            _ausdruck_erlaubt(ausdruck, job, frueher, fehler)
        if sid:
            frueher[sid] = _ausgaben(art)
        soll_env = SCHRITT_ENV.get((job, sid))
        if (s.get("env") or None) != soll_env:
            fehler("schritt_env", "%s: env muss %s sein" % (ort, soll_env or "leer"))
        soll_with = WITH_SOLL.get((job, sid))
        if soll_with is not None and s.get("with") != soll_with:
            fehler("action_konfig", "%s: with weicht von der geprüften Konfiguration ab" % ort)
        if art[0] == "checkout" and s.get("with") != CHECKOUT_WITH:
            fehler("action_konfig", "%s: checkout nur mit persist-credentials: false" % ort)
        if art == ("action", "actions/upload-artifact") and (job, sid) != ("signieren", "upload_nachweis"):
            fehler("installer_artefakt", "%s: einziges GitHub-Artefakt sind die JSON-Nachweise" % ort)
    if arten != ABLAUF[job]:
        fehler("reihenfolge", "Job %s: Schrittfolge weicht vom Signaturpfad ab (%s)"
               % (job, ", ".join("%s:%s" % (a[1], a[2] or a[0] or "-") for a in arten)))


def _ausgaben(art):
    if art[0] == "helfer":
        return set(sig.AUSGABEN[art[1]])
    if art[0] in ("action", "checkout"):
        return set(ACTIONS.get(art[1] or "actions/checkout", {}).get("ausgaben", ()))
    return set()


def _uses(job, ort, s, fehler):
    name = str(s["uses"]).split("@", 1)[0].lower()
    stand = ACTIONS.get(name)
    if not stand:
        return  # bereits als pin gemeldet
    mit = s.get("with") or {}
    if not isinstance(mit, dict):
        fehler("action_eingabe", "%s: with ist kein Mapping" % ort)
        return
    for k in mit:
        if k not in stand["eingaben"]:
            fehler("action_eingabe", "%s: %s kennt keine Eingabe %s (Stand %s)" % (ort, name, k, stand["tag"]))
    for k in stand["pflicht"]:
        if k not in mit:
            fehler("action_pflicht", "%s: Pflichteingabe %s fehlt" % (ort, k))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    pfad = argv[0] if argv else WORKFLOW
    with open(pfad, encoding="utf-8") as fh:
        befunde = pruefe_workflow(fh.read())
    for b in befunde:
        print("BEFUND [%s] %s" % (b["code"], b["meldung"]))
    print("%s: %s" % (os.path.relpath(pfad, REPO), "ohne Befund" if not befunde else "%d Befund(e)" % len(befunde)))
    return 0 if not befunde else 1


if __name__ == "__main__":
    sys.exit(main())
