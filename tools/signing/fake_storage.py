#!/usr/bin/env python3
"""NUR für Tests und den lokalen Trockenlauf: Nachbildung der privaten Signatur-Artefaktablage – ohne Netz.

Bildet den Vertrag der Ablage nach (Basis https://cockpit.insight-it.de/api/signing/artifacts):
    PUT    /{build_id}/{kind}      kind = unsigned | signed | quality, Kopf X-Artifact-SHA256, ?replace=1 zum Ersetzen
    GET    /{build_id}/{kind}      Datei-Bytes
    GET    /{build_id}/manifest    {build_id, artifacts:[{kind, filename, sha256, size, uploaded_at}]}
    DELETE /{build_id}             alle Artefakte des Builds
    GET    /api/signing/health     {ok: true} ohne Token
Fehler: 400 ungültige ID/Datei, 401 Token fehlt/falsch, 404 nicht vorhanden, 409 vorhanden ohne replace,
413 zu groß, 422 Hash/Format/Quality ungültig, 503 Token serverseitig nicht konfiguriert. Retention 7 Tage.

Zustand liegt in einem Ordner (damit getrennte Prozesse – Workflow-Schritte im Trockenlauf, curl-Double – dieselbe
Ablage sehen):
    konfig.json      {"token": str|null, "max_groesse": int, "jetzt": iso|null, "stoerung": {...}}
    daten/<build_id>/<kind>, daten/<build_id>/meta.json
    protokoll.jsonl  je Anfrage {quelle, methode, pfad, auth: ok|fehlt|falsch|-, status} – nie das Token selbst
Störungen (nur Tests): {"status": {"PUT signed": 409}, "get_falsch": ["unsigned"], "manifest_sha": {"signed": "<hex>"}}

Transporte: DateiTransport(ordner) für artifact_signing (SIGN_STORAGE_FAKE), `fake_storage.py curl …` als curl-Double
für die von vorbereiten.py gedruckten Befehle (Teilmenge der curl-Optionen, Token nur über -H @-).
"""
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import tempfile
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import artifact_signing as sig  # noqa: E402

PRAEFIX = "/api/signing/artifacts/"
HEALTH = "/api/signing/health"
RETENTION = dt.timedelta(days=7)
MZ = b"MZ"


def _jetzt(konfig):
    if konfig.get("jetzt"):
        return dt.datetime.fromisoformat(konfig["jetzt"])
    return dt.datetime.now(dt.timezone.utc)


def _json(obj, status=200):
    return status, json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _gueltige_build_id(bid):
    if not sig.BUILD_ID_RE.fullmatch(bid or ""):
        return False
    try:
        dt.datetime.strptime(bid, "%Y%m%d-%H%M%S")
    except ValueError:
        return False
    return True


class FakeAblage:
    def __init__(self, ordner, quelle="workflow"):
        self.ordner, self.quelle = ordner, quelle
        os.makedirs(os.path.join(ordner, "daten"), exist_ok=True)

    # ---------- Einrichtung (Tests/Trockenlauf)
    @staticmethod
    def einrichten(ordner, token, max_groesse=sig.MAX_GROESSE, jetzt=None, stoerung=None):
        os.makedirs(os.path.join(ordner, "daten"), exist_ok=True)
        with open(os.path.join(ordner, "konfig.json"), "w", encoding="utf-8") as fh:
            json.dump({"token": token, "max_groesse": max_groesse, "jetzt": jetzt, "stoerung": stoerung or {}}, fh)
        return FakeAblage(ordner, quelle="einrichtung")

    def konfig(self):
        try:
            with open(os.path.join(self.ordner, "konfig.json"), encoding="utf-8") as fh:
                return json.load(fh)
        except OSError:
            return {"token": None, "max_groesse": sig.MAX_GROESSE, "jetzt": None, "stoerung": {}}

    def aendere_konfig(self, **werte):
        k = self.konfig()
        k.update(werte)
        with open(os.path.join(self.ordner, "konfig.json"), "w", encoding="utf-8") as fh:
            json.dump(k, fh)

    def roh_ablegen(self, build_id, kind, daten, uploaded_at=None):
        """Ohne Prüfung ablegen (simuliert manipulierte oder fehlerhafte Server-Inhalte)."""
        self._speichern(build_id, kind, daten, hashlib.sha256(daten).hexdigest(),
                        uploaded_at or _jetzt(self.konfig()).isoformat(timespec="seconds"))

    # ---------- Speicher
    def _bdir(self, build_id):
        return os.path.join(self.ordner, "daten", build_id)

    def _meta(self, build_id):
        try:
            with open(os.path.join(self._bdir(build_id), "meta.json"), encoding="utf-8") as fh:
                return json.load(fh)
        except OSError:
            return {}

    def _speichern(self, build_id, kind, daten, sha, uploaded_at):
        bdir = self._bdir(build_id)
        os.makedirs(bdir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=bdir, prefix=".neu-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(daten)
        os.replace(tmp, os.path.join(bdir, kind))
        meta = self._meta(build_id)
        meta[kind] = {"kind": kind, "filename": sig.ablage_dateiname(build_id, kind), "sha256": sha, "size": len(daten),
                      "uploaded_at": uploaded_at}
        fd, tmp = tempfile.mkstemp(dir=bdir, prefix=".meta-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        os.replace(tmp, os.path.join(bdir, "meta.json"))

    def _loeschen(self, build_id):
        bdir = self._bdir(build_id)
        for name in os.listdir(bdir):
            os.remove(os.path.join(bdir, name))
        os.rmdir(bdir)

    def _retention(self, konfig):
        grenze = _jetzt(konfig) - RETENTION
        for bid in os.listdir(os.path.join(self.ordner, "daten")):
            zeiten = [dt.datetime.fromisoformat(m["uploaded_at"]) for m in self._meta(bid).values()]
            if zeiten and min(zeiten) < grenze:
                self._loeschen(bid)

    def _protokoll(self, methode, pfad, auth, status):
        with open(os.path.join(self.ordner, "protokoll.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"quelle": self.quelle, "methode": methode, "pfad": pfad, "auth": auth,
                                 "status": status}) + "\n")

    def protokoll(self):
        pfad = os.path.join(self.ordner, "protokoll.jsonl")
        if not os.path.exists(pfad):
            return []
        with open(pfad, encoding="utf-8") as fh:
            return [json.loads(z) for z in fh if z.strip()]

    def inhalt(self, build_id, kind):
        try:
            with open(os.path.join(self._bdir(build_id), kind), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    # ---------- HTTP
    def anfrage(self, methode, url, kopf, body):
        t = urllib.parse.urlsplit(url)
        konfig = self.konfig()
        status, daten, auth = self._bearbeite(methode, t, {k.lower(): v for k, v in (kopf or {}).items()}, body, konfig)
        self._protokoll(methode, t.path + ("?" + t.query if t.query else ""), auth, status)
        return status, daten

    def _bearbeite(self, methode, t, kopf, body, konfig):
        if t.scheme != "https" or t.hostname != sig.STORAGE_HOST or t.port not in (None, 443):
            return 400, b"", "-"
        if t.path == HEALTH and methode == "GET":
            return 200, b'{"ok":true}', "-"
        if not t.path.startswith(PRAEFIX):
            return 404, b"", "-"
        if not konfig.get("token"):
            return 503, b"", "-"
        geliefert = kopf.get("authorization")
        if not geliefert:
            return 401, b"", "fehlt"
        if not hmac.compare_digest(geliefert.encode("utf-8"), ("Bearer " + konfig["token"]).encode("utf-8")):
            return 401, b"", "falsch"
        self._retention(konfig)
        teile = t.path[len(PRAEFIX):].split("/")
        if not 1 <= len(teile) <= 2 or not _gueltige_build_id(teile[0]):
            return 400, b"", "ok"
        bid = teile[0]
        art = teile[1] if len(teile) == 2 else None
        stoerung = konfig.get("stoerung") or {}
        erzwungen = (stoerung.get("status") or {}).get("%s %s" % (methode, art or ""))
        if erzwungen:
            return int(erzwungen), b"", "ok"
        if methode == "DELETE" and art is None and not t.query:
            if not os.path.isdir(self._bdir(bid)):
                return 404, b"", "ok"
            self._loeschen(bid)
            return 200, b'{"deleted":true}', "ok"
        if methode == "GET" and art == "manifest" and not t.query:
            meta = self._meta(bid)
            if not meta:
                return 404, b"", "ok"
            artefakte = []
            for kind in sig.KINDS:
                if kind in meta:
                    eintrag = dict(meta[kind])
                    eintrag["sha256"] = (stoerung.get("manifest_sha") or {}).get(kind, eintrag["sha256"])
                    artefakte.append(eintrag)
            return (*_json({"build_id": bid, "artifacts": artefakte}), "ok")
        if art not in sig.KINDS:
            return 400, b"", "ok"
        if methode == "GET" and not t.query:
            daten = self.inhalt(bid, art)
            if daten is None:
                return 404, b"", "ok"
            if art in (stoerung.get("get_falsch") or []):
                daten = daten[:-1] + bytes([daten[-1] ^ 0x01])
            return 200, daten, "ok"
        if methode != "PUT":
            return 400, b"", "ok"
        abfrage = urllib.parse.parse_qs(t.query, keep_blank_values=True)
        if set(abfrage) - {"replace"} or abfrage.get("replace", ["1"]) != ["1"]:
            return 400, b"", "ok"
        body = body or b""
        if len(body) > int(konfig.get("max_groesse") or sig.MAX_GROESSE):
            return 413, b"", "ok"
        sha = (kopf.get("x-artifact-sha256") or "").strip()
        if not sig.SHA256_RE.fullmatch(sha) or hashlib.sha256(body).hexdigest() != sha:
            return 422, b"", "ok"
        if art == "quality":
            try:
                sig.pruefe_quality(json.loads(body.decode("utf-8")), bid)
            except (UnicodeDecodeError, ValueError, sig.SigningError):
                return 422, b"", "ok"
        elif not body.startswith(MZ) or sig.NSIS_KENNUNG not in body:
            return 422, b"", "ok"
        if self.inhalt(bid, art) is not None and "replace" not in abfrage:
            return 409, b"", "ok"
        self._speichern(bid, art, body, sha, _jetzt(konfig).isoformat(timespec="seconds"))
        return (*_json({"build_id": bid, "kind": art, "sha256": sha, "size": len(body)}, 201), "ok")


class DateiTransport:
    """Transport für artifact_signing (SIGN_STORAGE_FAKE=<ordner>): gleiche Schnittstelle wie HttpsTransport."""

    def __init__(self, ordner, quelle="workflow"):
        self.ablage = FakeAblage(ordner, quelle)

    def __call__(self, methode, url, kopf, body, max_antwort):
        sig.pruefe_storage_url(url)
        status, daten = self.ablage.anfrage(methode, url, kopf, body)
        if len(daten) > max_antwort:
            raise sig.SigningError("storage_zu_gross", "Antwort der Ablage größer als %d Bytes" % max_antwort)
        return status, daten


# ---------------------------------------------------------------- curl-Double (nur Tests)

CURL_SCHALTER = {"-f", "--fail", "-s", "--silent", "-S", "--show-error", "-fsS", "--tlsv1.2"}
CURL_MIT_WERT = {"-X", "--request", "-H", "--header", "--data-binary", "-o", "--output", "--proto", "--max-time"}


def curl_main(argv, stdin=None):
    """Teilmenge von curl für die gedruckten Befehle. Exit 22 bei HTTP ≥ 400 mit -f, 2 bei unbekannter Option."""
    stdin = sys.stdin.buffer if stdin is None else stdin
    ordner = os.environ.get("FAKE_STORAGE_ORDNER")
    methode, kopf, body, ausgabe, url, fail, proto = None, {}, None, None, None, False, None
    if any("authorization" in a.lower() for a in argv):
        print("curl-Double: Authorization nie auf der Kommandozeile (nur -H @-)", file=sys.stderr)
        return 2
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in CURL_SCHALTER:
            fail = fail or a in ("-f", "--fail", "-fsS")
            i += 1
            continue
        if a in CURL_MIT_WERT:
            if i + 1 >= len(argv):
                return 2
            wert = argv[i + 1]
            if a in ("-X", "--request"):
                methode = wert
            elif a in ("-H", "--header"):
                zeilen = stdin.read().decode("utf-8").splitlines() if wert == "@-" else [wert]
                for zeile in zeilen:
                    if ":" in zeile:
                        k, v = zeile.split(":", 1)
                        kopf[k.strip()] = v.strip()
            elif a == "--data-binary":
                if not wert.startswith("@"):
                    return 2
                with open(wert[1:], "rb") as fh:
                    body = fh.read()
            elif a in ("-o", "--output"):
                ausgabe = wert
            elif a == "--proto":
                proto = wert
            i += 2
            continue
        if a.startswith("-"):
            print("curl-Double: Option %s nicht unterstützt" % a, file=sys.stderr)
            return 2
        if url is not None:
            return 2
        url = a
        i += 1
    if proto != "=https" or not url or not ordner:
        print("curl-Double: --proto =https, URL und FAKE_STORAGE_ORDNER nötig", file=sys.stderr)
        return 2
    methode = methode or ("PUT" if body is not None else "GET")
    if urllib.parse.urlsplit(url).scheme != "https":
        return 1
    status, daten = FakeAblage(ordner, quelle="curl").anfrage(methode, url, kopf, body)
    if status >= 400 and fail:
        print("curl: (22) The requested URL returned error: %d" % status, file=sys.stderr)
        return 22
    if ausgabe:
        with open(ausgabe, "wb") as fh:
            fh.write(daten)
    else:
        sys.stdout.buffer.write(daten)
        sys.stdout.flush()
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["curl"]:
        return curl_main(argv[1:])
    print("Aufruf: fake_storage.py curl <curl-Argumente>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
