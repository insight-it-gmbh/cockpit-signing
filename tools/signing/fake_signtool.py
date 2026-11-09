#!/usr/bin/env python3
"""NUR für den lokalen Trockenlauf (tools/signing/trockenlauf.py): ahmt `signtool sign` und
`signtool verify /pa /tw /v` nach – ohne Azure, ohne Zertifikat, ohne Kryptografie.

Erzeugt nie eine echte Signatur. Der angehängte WIN_CERTIFICATE-Block enthält statt PKCS#7 eine als FAKE markierte
JSON-Beschreibung; jede Ausgabe beginnt mit der Kennung FAKE-SIGNTOOL. artifact_signing.py wertet diese Kennung
außerhalb des Trockenlaufs als Fehler und schreibt im Trockenlauf nur Nachweise mit Status „ungueltig“.

Aufruf wie signtool (Argumente so, wie das PowerShell-Modul ArtifactSigning 0.1.8 sie bildet):
    sign /v /debug /fd SHA256 /tr <url> /td SHA256 /dlib <dll> /dmdf <metadata.json> /d <text> <dateien…>
    verify /pa /tw /v <datei>
Umgebung:
    FAKE_SIGNTOOL_MODUS        ok | fehler | ohne-signatur | warnung-ohne-signatur | selbstsigniert | ohne-zeitstempel |
                               ohne-zeitstempel-exit0 | falscher-herausgeber | fremde-ca | manipulieren | verify-abgelehnt
    FAKE_SIGNTOOL_HERAUSGEBER  Inhaber des Blattzertifikats (Standard: Trockenlauf Herausgeber GmbH)
    FAKE_SIGNTOOL_PROTOKOLL    Datei für JSON-Zeilen je Aufruf (argv, Metadaten)
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import artifact_signing as sig  # noqa: E402

KENNUNG = sig.FAKE_KENNUNG + ": Trockenlauf, keine echte Signatur"
BLOB_KENNUNG = b"FAKE-SIGNTOOL-KEINE-ECHTE-SIGNATUR\0"
STANDARD_HERAUSGEBER = "Trockenlauf Herausgeber GmbH"
WURZEL = "Trockenlauf Root CA"
ZWISCHEN = "Microsoft ID Verified Code Signing PCA (Trockenlauf)"
AUSSTELLER = sig.AUSSTELLER_PRAEFIX + "TROCKENLAUF CA 00"
ZEITSTEMPEL = "Mon Nov 09 12:00:00 2026"
MODI = ("ok", "fehler", "ohne-signatur", "warnung-ohne-signatur", "selbstsigniert", "ohne-zeitstempel",
        "ohne-zeitstempel-exit0", "falscher-herausgeber", "fremde-ca", "manipulieren", "verify-abgelehnt")


def _modus():
    modus = os.environ.get("FAKE_SIGNTOOL_MODUS") or "ok"
    if modus not in MODI:
        raise SystemExit("Unbekannter FAKE_SIGNTOOL_MODUS %r" % modus)
    return modus


def _protokoll(eintrag):
    pfad = os.environ.get("FAKE_SIGNTOOL_PROTOKOLL")
    if pfad:
        with open(pfad, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(eintrag, ensure_ascii=False) + "\n")


def pe_pruefsumme(data, pruefsumme_off):
    """PE-Prüfsumme wie ImageHlp (16-Bit-Summe ohne Prüfsummenfeld, plus Dateilänge)."""
    summe = 0
    roh = data + (b"\0" if len(data) % 2 else b"")
    for (wort,) in struct.iter_unpack("<H", roh):
        summe += wort
    for (wort,) in struct.iter_unpack("<H", data[pruefsumme_off:pruefsumme_off + 4]):
        summe -= wort
    while summe >> 16:
        summe = (summe & 0xFFFF) + (summe >> 16)
    return (summe + len(data)) & 0xFFFFFFFF


def kette_fuer(modus, herausgeber):
    if modus == "selbstsigniert":
        return [[herausgeber, herausgeber]]
    if modus == "falscher-herausgeber":
        herausgeber = "Fremdfirma Beispiel GmbH"
    if modus == "fremde-ca":
        return [["Beispiel Test Root", "Beispiel Test Root"], ["Beispiel Code Signing CA", "Beispiel Test Root"],
                [herausgeber, "Beispiel Code Signing CA"]]
    return [[WURZEL, WURZEL], [ZWISCHEN, WURZEL], [AUSSTELLER, ZWISCHEN], [herausgeber, AUSSTELLER]]


def signiere_bytes(data, beschreibung):
    """Wie signtool: auf 8 Byte auffüllen, WIN_CERTIFICATE anhängen, Verzeichnis und Prüfsumme setzen."""
    layout = sig.pe_layout(data)
    if layout["sec_va"] or layout["sec_size"]:
        raise ValueError("Datei ist bereits signiert")
    roh = bytearray(data + b"\0" * ((-len(data)) % 8))
    beschreibung = dict(beschreibung, digest=sig.authenticode_sha256(bytes(roh), layout))
    blob = BLOB_KENNUNG + json.dumps(beschreibung, ensure_ascii=False, sort_keys=True).encode("utf-8")
    eintrag = struct.pack("<IHH", 8 + len(blob), sig.WIN_CERT_REVISION, sig.WIN_CERT_PKCS) + blob
    eintrag += b"\0" * ((-len(eintrag)) % 8)
    struct.pack_into("<II", roh, layout["secdir_off"], len(roh), len(eintrag))
    roh += eintrag
    struct.pack_into("<I", roh, layout["pruefsumme_off"], pe_pruefsumme(bytes(roh), layout["pruefsumme_off"]))
    return bytes(roh)


SCHALTER = {"/v", "/debug", "/as", "/ph", "/nph", "/pa", "/tw", "/all", "/q"}


def _optionen(args, mit_wert):
    """Nur bekannte signtool-Schalter sind Optionen; alles andere ist eine Datei (unter Linux beginnen Pfade mit /)."""
    optionen, dateien, i = {}, [], 0
    while i < len(args):
        a = args[i]
        if a in mit_wert:
            if i + 1 >= len(args):
                raise SystemExit("SignTool Error: Option %s ohne Wert" % a)
            optionen[a] = args[i + 1]
            i += 2
        elif a in SCHALTER:
            optionen[a] = True
            i += 1
        else:
            dateien.append(a)
            i += 1
    return optionen, dateien


def cmd_sign(args):
    modus = _modus()
    optionen, dateien = _optionen(args, {"/fd", "/tr", "/td", "/dlib", "/dmdf", "/d", "/du"})
    print(KENNUNG)
    fehler = []
    if optionen.get("/fd") != "SHA256" or optionen.get("/td") != "SHA256":
        fehler.append("Digest muss SHA256 sein")
    if not str(optionen.get("/tr", "")).startswith("http"):
        fehler.append("RFC-3161-Zeitstempel (/tr) fehlt")
    if not os.path.isfile(str(optionen.get("/dlib", ""))):
        fehler.append("Dlib fehlt")
    metadaten = None
    try:
        with open(str(optionen.get("/dmdf", "")), encoding="utf-8") as fh:
            metadaten = json.load(fh)
    except (OSError, ValueError):
        fehler.append("Metadaten-Datei (/dmdf) fehlt oder ist kein JSON")
    if not dateien:
        fehler.append("Keine Datei angegeben")
    _protokoll({"befehl": "sign", "argv": ["sign"] + args, "metadaten": metadaten, "modus": modus})
    if fehler:
        print("SignTool Error: " + "; ".join(fehler))
        return 1
    if modus == "fehler":
        print("SignTool Error: An unexpected internal error has occurred (Trockenlauf).")
        print("Number of errors: 1")
        return 1
    if modus == "ohne-signatur":
        print("Number of files successfully Signed: 0\nNumber of warnings: 0\nNumber of errors: 0")
        return 0
    if modus == "warnung-ohne-signatur":
        print("SignTool Warning: Signing skipped (Trockenlauf).\nNumber of warnings: 1\nNumber of errors: 0")
        return 2
    herausgeber = os.environ.get("FAKE_SIGNTOOL_HERAUSGEBER") or STANDARD_HERAUSGEBER
    for datei in dateien:
        with open(datei, "rb") as fh:
            data = fh.read()
        if modus == "manipulieren":
            data = data[:-1] + bytes([data[-1] ^ 0xFF])
        beschreibung = {"kette": kette_fuer(modus, herausgeber),
                        "zeitstempel": None if modus.startswith("ohne-zeitstempel") else ZEITSTEMPEL,
                        "tw_ignorieren": modus == "ohne-zeitstempel-exit0", "beschreibung": optionen.get("/d")}
        with open(datei, "wb") as fh:
            fh.write(signiere_bytes(data, beschreibung))
        print("Successfully signed: %s" % datei)
    print("\nNumber of files successfully Signed: %d\nNumber of warnings: 0\nNumber of errors: 0" % len(dateien))
    return 0


def _fehlerende(text):
    print("SignTool Error: " + text)
    print("\nNumber of files successfully Verified: 0\nNumber of warnings: 0\nNumber of errors: 1")
    return 1


def _kette_drucken(kette, basis=1):
    for ebene, (fuer, von) in enumerate(kette, start=basis):
        einzug = "    " * ebene
        print("%sIssued to: %s\n%sIssued by: %s\n%sExpires:   Sun Apr 16 20:44:40 2045\n%sSHA1 hash: %s"
              % (einzug, fuer, einzug, von, einzug, einzug, hashlib.sha1(fuer.encode("utf-8")).hexdigest().upper()))


def cmd_verify(args):
    modus = _modus()
    optionen, dateien = _optionen(args, set())
    _protokoll({"befehl": "verify", "argv": ["verify"] + args, "modus": modus})
    print(KENNUNG)
    if len(dateien) != 1 or not {"/pa", "/v"} <= set(optionen):
        return _fehlerende("Aufruf erwartet: verify /pa [/tw] /v <datei>")
    datei = dateien[0]
    print("Verifying: %s\n" % datei)
    with open(datei, "rb") as fh:
        data = fh.read()
    layout = sig.pe_layout(data)
    tabelle = sig.zertifikatstabelle(data, layout)
    if not tabelle:
        return _fehlerende("No signature found.")
    blob = data[tabelle[0]["offset"] + 8:tabelle[0]["offset"] + tabelle[0]["laenge"]]
    if not blob.startswith(BLOB_KENNUNG):
        return _fehlerende("Signature format not recognised by the dry-run tool.")
    info = json.loads(blob[len(BLOB_KENNUNG):].decode("utf-8"))
    digest = sig.authenticode_sha256(data, layout)
    if digest != info["digest"]:
        return _fehlerende("WinVerifyTrust returned error: 0x80096010\n\tThe digital signature of the object did not verify.")
    if modus == "verify-abgelehnt":
        return _fehlerende("A certificate chain processed, but terminated in a root certificate which is not trusted "
                           "by the trust provider.")
    print("Signature Index: 0 (Primary Signature)\nHash of file (sha256): %s\n\nSigning Certificate Chain:" % digest.upper())
    _kette_drucken(info["kette"])
    warnungen = 0
    if info["zeitstempel"]:
        print("The signature is timestamped: %s\nTimestamp Verified by:" % info["zeitstempel"])
        _kette_drucken([[WURZEL, WURZEL], ["Microsoft Public RSA Timestamping CA (Trockenlauf)", WURZEL],
                        ["Microsoft Public RSA Time Stamping Authority (Trockenlauf)",
                         "Microsoft Public RSA Timestamping CA (Trockenlauf)"]])
    else:
        print("File is not timestamped.")
        if "/tw" in optionen and not info.get("tw_ignorieren"):
            print("SignTool Warning: The signature is not timestamped.")
            warnungen = 1
    print("\nSuccessfully verified: %s\n\nNumber of files successfully Verified: 1\nNumber of warnings: %d\n"
          "Number of errors: 0" % (datei, warnungen))
    return 2 if warnungen else 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["sign"]:
        return cmd_sign(argv[1:])
    if argv[:1] == ["verify"]:
        return cmd_verify(argv[1:])
    print("SignTool Error: Trockenlauf-Werkzeug kennt nur sign und verify")
    return 1


if __name__ == "__main__":
    sys.exit(main())
