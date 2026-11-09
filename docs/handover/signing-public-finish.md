# Handover signing-public

Paket: öffentliches Signatur-Repository mit privater HTTPS-Artefaktablage (Migration des Signaturpfads aus dem
bisherigen privaten Repository). Kein GitHub-Repository angelegt, kein Push, kein Deploy, keine echten Tokens.

## Erledigt

- Workflow `.github/workflows/sign-cockpit.yml`: Transport nur über `https://cockpit.insight-it.de/api/signing/artifacts`
  (Bearer aus Repo-Secret `SIGNING_STORAGE_TOKEN`, nur im env der sechs Ablage-Schritte). Kein Pre-Release, kein
  Installer-Artefakt; einziges GitHub-Artefakt sind die JSON-Nachweise. Job `tests` prüft nur dieses Repository
  (kein privater Checkout, kein pip, kein .NET).
- `tools/signing/artifact_signing.py`: neue Schritte `qualitaet` (quality.json: `bestanden:true`, Build-ID,
  `remote_e2e_fps`), `laden` (Manifest + Download), `hochladen` (PUT signed mit `X-Artifact-SHA256`, ohne replace),
  `ablage-pruefen` (Manifest + erneuter Download bitgleich). Repository öffentlich erlaubt, `full_name` gegen
  `GITHUB_REPOSITORY` geprüft (`repo_unbekannt`). Produktiver Transport `HttpsTransport` (nur dieser Host, TLS ≥ 1.2,
  keine Weiterleitungen); Fake-Transport nur über `SIGN_STORAGE_FAKE` (auf GitHub-Runnern verboten).
- `tools/signing/fake_storage.py`: Fake der Ablage nach Vertrag (inkl. 400/401/404/409/413/422/503, replace, Retention
  7 Tage) als Datei-Transport und curl-Double.
- `tools/signing/vorbereiten.py`: druckt curl-Befehle (Token nur per `printf | curl -H @-`), `manifest-pruefen`,
  Laden des signierten Installers aus der Ablage; Ablage-Löschung nur für eigenen Upload ohne grünen Lauf.
- `tools/signing/workflow_check.py`: Secret-Ort, Release-/Installer-Artefakt-Verbot, Host-Allowlist, eigener
  Secret-Scan (ersetzt die Abhängigkeit vom privaten Qualitätsmodul).
- `tools/signing/trockenlauf.py`: 52 Szenarien (inkl. öffentliches Repository, Token-, Quality-, Ablage-Fehler).
- `docs/release-signing.md`, `README.md`.

## Offen (Orchestrator / Freigabeverantwortliche)

- GitHub-Repository anlegen, Environment/Variablen/Secret setzen, Branch-Schutz (Runbook, Einrichtung).
- Ablage-Modul (Paket signing-storage) deployen; Token erzeugen und als Repo-Secret hinterlegen.
- Qualitätslauf des Cockpits muss `quality.json` im Vertragsformat liefern (`bestanden`, `build_id`, `remote_e2e_fps`).
- Konsistenzprüfungen gegen privaten Code (Pin-Liste des Qualitäts-Gates, `installer.nsi`-Konstanten,
  `check_signing_workflow`) sind hier entfallen und gehören in das private Repository.
- Retention-Bezugspunkt der echten Ablage (erster oder letzter Upload) gegen den Fake abgleichen.

## Testbefehle

```bash
python3 tools/test_artifact_signing.py      # erwartet: 56 Tests OK (1 Skip ohne PyYAML)
python3 tools/signing/workflow_check.py     # erwartet: ohne Befund
python3 tools/signing/trockenlauf.py        # erwartet: 52/52 Szenarien wie erwartet
uv run --no-project --with pyyaml python3 tools/test_artifact_signing.py   # optional: YAML-Gegenprobe ohne Skip
```
