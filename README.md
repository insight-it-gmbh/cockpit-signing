# cockpit-signing

Signaturpfad für den Insight-IT-Fernwartungs-Installer (NSIS) mit Microsoft Artifact Signing.

- `.github/workflows/sign-cockpit.yml` – manueller, freigabepflichtiger Workflow (`workflow_dispatch`, Environment
  `release-signing` mit Pflicht-Reviewern, Azure-Anmeldung per OIDC ohne Client-Geheimnis).
- `tools/signing/` – Helfer nur mit der Python-Standardbibliothek: Prüfung der Installer, Nachprüfung der Signatur,
  Client der privaten Artefaktablage, statische Workflow-Prüfung, lokaler Trockenlauf mit Fake-Werkzeugen.
- `tools/test_artifact_signing.py` – Tests (ohne Netz, ohne Azure, ohne echte Installer).
- `docs/release-signing.md` – Runbook: Einrichtung, erste Produktivprobe, Abbruchcodes, Grenzen.

**Dieses Repository enthält keine Installer und keine Zugangsdaten.** Installer und Qualitätsnachweise liegen nur in
einer privaten HTTPS-Ablage; der Workflow lädt sie mit einem Token aus einem Repo-Secret und legt das signierte
Ergebnis dort wieder ab. Als GitHub-Artefakt entstehen nur JSON-Nachweise (Hashes, Zertifikatsnamen, Testwerte).
Es gibt keine Releases mit Installern.

```bash
python3 tools/test_artifact_signing.py        # alle Tests
python3 tools/signing/workflow_check.py       # statische Prüfung des Workflows
python3 tools/signing/trockenlauf.py          # kompletter Lauf mit Fake-signtool und Fake-Ablage
```

Beiträge: Änderungen am Workflow nur per Pull-Request mit Review; Schreibrecht auf dieses Repository entspricht
Signierrecht (siehe Runbook, „Grenzen“).
