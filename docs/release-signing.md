# Release-Signatur des Fernwartungs-Installers (Microsoft Artifact Signing, private Artefaktablage)

Stand 09.11.2026. Dieses Dokument enthält **keine** echten Kontowerte, IDs, Tokens oder Geheimnisse. Alle Konto-,
Portal- und GitHub-Einstellungen nimmt ausschließlich die freigebende Person mit Admin-Rechten vor (Abschnitt
„Einrichtung“). Implementiert und lokal geprüft ist der Pfad bis zum Trockenlauf; der erste echte Signaturvorgang ist
die „Erste Produktivprobe“ am Ende.

## Ablauf

```
Build (build.sh, Build-ID JJJJMMTT-HHMMSS) + quality.json (Qualitätslauf: bestanden, remote_e2e_fps)
  → tools/signing/vorbereiten.py: Installer und quality.json lokal prüfen, Befehle drucken
  → curl PUT <ABLAGE>/<BUILD_ID>/unsigned und …/quality (Bearer-Token aus SIGNING_STORAGE_TOKEN), Manifest gegenprüfen
  → gh workflow run sign-cockpit.yml
Workflow .github/workflows/sign-cockpit.yml (nur workflow_dispatch, nur Zweig main)
  ├─ tests        Tests dieses Repositorys (Unit, Mutationen, Trockenlauf) und statische Workflow-Prüfung
  ├─ vorpruefung  Repository (full_name), Environment-Schutz, Qualitätsnachweis aus der Ablage,
  │               Manifest + Download des unsignierten Installers, SHA-256, NSIS, Hersteller, Build-ID, unsigniert
  └─ signieren    erst nach tests + vorpruefung und nach Freigabe im Environment release-signing:
                  Qualität + Installer erneut laden und prüfen → azure/login (OIDC) → azure/artifact-signing-action
                  → Azure-Sitzung beenden → Nachprüfung (signtool verify /pa /tw /v, Inhalt, Kette, Herausgeber,
                  Zeitstempel, Hash) → PUT <BUILD_ID>/signed → Manifest + erneuter Download, Hash = geprüfte Datei
                  → Nachweise (nur JSON) als GitHub-Artefakt signatur-nachweis-<BUILD_ID>
Lokal: Nachweise laden und binden (nachweis-pruefen), signierten Installer aus der Ablage laden (ergebnis-pruefen)
Cockpit /api/quality: release-metadata.json + signatur-nachweis.json erfassen → Gates → Vier-Augen-Freigabe
```

Alle Schritte rufen `tools/signing/artifact_signing.py` (nur Python-Standardbibliothek) ohne Argumente auf; Werte kommen
ausschließlich über `env`. Jede Abweichung bricht mit „FEHLER [code]“ ab; ohne bestandene Nachprüfung wird nichts in die
Ablage geschrieben und kein Nachweis erzeugt. Das PowerShell-Modul der Action wertet signtool-Exit 2 (Warnungen) als
Erfolg – deshalb ist die Nachprüfung Pflicht und nicht abschaltbar.

**Code im Signier-Job:** kein `pip`, kein eigener Drittcode; die eigenen Helfer nutzen nur die Python-Standardbibliothek.
Die Microsoft-Action `azure/artifact-signing-action` (v2.0.0, per SHA gepinnt) installiert jedoch zur Laufzeit
versionierte Microsoft-Abhängigkeiten: das PowerShell-Modul ArtifactSigning 0.1.8 aus der PowerShell Gallery und bei
Bedarf NuGet-Pakete in den von ihrer `action.yml` festgelegten Versionen (Microsoft.Windows.SDK.BuildTools
10.0.26100.4188, Microsoft.ArtifactSigning.Client 1.0.128, für Nicht-PE-Dateien das Sign-CLI 0.9.1-beta.26227.3). Diese
sind versions-, aber nicht hashgepinnt; `cache-dependencies: "false"` verhindert, dass sie aus einem (manipulierbaren)
Actions-Cache kommen. Beim Aktualisieren der Action diese Versionen in der neuen `action.yml` nachlesen.

## Öffentliches Repository, private Artefakte

Dieses Repository enthält nur Workflow, Helfer, Tests und Doku. Es darf **öffentlich** sein (`repository.private=false`
ist erlaubt):

- **Pflicht-Reviewer funktionieren im öffentlichen Repository.** Environment-Schutzregeln (Required reviewers,
  Zweigregeln, „Prevent self-review“) setzt GitHub für öffentliche Repositories auf jedem Plan durch; für private
  Repositories nur mit Enterprise. Die Vorprüfung bricht trotzdem ab, wenn die Regeln fehlen (`umgebung_ungeschuetzt`,
  `umgebung_zweige`, `umgebung_admin_bypass`).
- **Kundenbinaries bleiben privat.** Kunden-Installer enthalten kundenspezifische Zugangsdaten. Sie liegen nur in der
  privaten Signatur-Artefaktablage (HTTPS, Bearer-Token) und gelangen nie in GitHub: kein Release, kein Pre-Release,
  kein Installer als Workflow-Artefakt, kein Installer im Log. Der Workflow lädt sie nur in das temporäre
  Arbeitsverzeichnis des Runners.
- **Logs und Artefakte eines öffentlichen Repositorys sind öffentlich.** Sie enthalten deshalb nur Build-ID, Hashes,
  Größen, Zertifikatsnamen und die Testwerte aus quality.json (`bestanden`, `remote_e2e_fps`) – keine Kundennamen,
  keine Pfade der Ablage, kein Token (GitHub maskiert das Secret zusätzlich). Dateinamen tragen nur die Build-ID.
- **`repository.full_name` wird validiert:** `full_name` aus der Ereignis-Nutzlast (`GITHUB_EVENT_PATH`) muss gültig
  sein und genau `GITHUB_REPOSITORY` entsprechen, `private` ein Wahrheitswert passend zu `visibility` sein – sonst
  `repo_unbekannt`, bevor das Token benutzt wird.
- Starten können den Workflow nur Personen mit Schreibrecht (`workflow_dispatch`). Es gibt keinen Pull-Request- oder
  Push-Trigger; Forks erhalten weder das Secret noch das OIDC-Token. **Schreibrecht wie Signierrecht behandeln**
  (siehe Grenzen).

## Artefaktablage (Vertrag)

Basis-URL produktiv: `https://cockpit.insight-it.de/api/signing/artifacts` (einziger erlaubter Host; der produktive
Transport lehnt andere Hosts, `http`, Ports und Weiterleitungen ab). Authentifizierung ausschließlich
`Authorization: Bearer <SIGNING_STORAGE_TOKEN>` – kein Setup-Key, keine Mitarbeiter-Tokens.

| Anfrage | Wirkung |
|---|---|
| `PUT /{build_id}/{kind}` | `kind` = `unsigned`, `signed` oder `quality`; Kopf `X-Artifact-SHA256`; nur NSIS-EXE bzw. quality.json mit `bestanden:true`, Build-ID und Testwerten; atomar; kein Überschreiben ohne `?replace=1` |
| `GET /{build_id}/{kind}` | Datei-Bytes |
| `GET /{build_id}/manifest` | `{build_id, artifacts:[{kind, filename, sha256, size, uploaded_at}]}` ohne Pfade/IPs/Secrets |
| `DELETE /{build_id}` | löscht alle Artefakte des Builds |
| `GET /api/signing/health` | `{ok:true}` ohne Token |

Fehler: 400 ungültige ID/Datei, 401 Token fehlt/falsch, 404 nicht vorhanden, 409 vorhanden ohne replace, 413 zu groß
(max. 200 MiB je Datei), 422 Hash/Format/Quality ungültig, 503 Token serverseitig nicht konfiguriert. Kein
Listen-Endpunkt. Dateinamen: `insight-fernwartung-<BUILD_ID>.exe`, beim Qualitätsnachweis `quality.json`.

**Retention:** Builds älter als 7 Tage entfernt die Ablage beim nächsten Zugriff selbst. Nach einem erfolgreichen
Lauf werden signierte Artefakte **nicht** von Hand gelöscht; der Build bleibt bis zur Retention liegen (Download und
Kontrolle in dieser Zeit). `aufraeumen` löscht nur einen **eigenen** Upload (PUT 201) ohne `signed`, dessen Lauf nie
gestartet wurde oder laut `gh run view` nachweislich fehlschlug bzw. abgebrochen wurde (`vorbereiten.py
loeschen-pruefen`). Bei 409, grünem, offenem oder unbekanntem Lauf und immer bei vorhandenem `signed` wird nichts gelöscht.

Im Workflow gilt der Vertrag so:

| Schritt | Anfragen | Zusatzprüfung |
|---|---|---|
| qualitaet | `GET manifest`, `GET quality` | Manifest-Hash = Download = Eingabe `quality_sha256`, Größe = Manifest, `bestanden:true`, Build-ID, `remote_e2e_fps` endliche Zahl > 0 |
| laden | `GET manifest`, `GET unsigned` | genau ein `unsigned`, Dateiname, Größe ≤ 200 MiB, SHA-256 = Eingabe, noch kein `signed`; Download = Manifest |
| hochladen | `PUT signed` mit `X-Artifact-SHA256` | nur die nachgeprüfte Datei, ohne `replace` (409 → `storage_konflikt`) |
| ablage-pruefen | `GET manifest`, `GET signed` | `signed` = geprüfter SHA-256 und Größe, `unsigned` unverändert, erneuter Download bitgleich |

## Was geprüft wird – Abbruchcodes

| Schritt | Prüfung | Codes |
|---|---|---|
| eingaben | Build-ID `JJJJMMTT-HHMMSS` (gültiger Zeitpunkt), SHA-256 des Installers und von quality.json, Version, Kanal, genau eins von Vorgänger-ID/Erstausrollung, Lauf von `refs/heads/main`, keine Überschreibung (`SIGN_GH`, `SIGN_SIGNTOOL`, `SIGN_TROCKENLAUF`, `SIGN_STORAGE_FAKE`) auf **jedem** GitHub-Runner (`GITHUB_ACTIONS=true` oder `RUNNER_ENVIRONMENT` gesetzt, auch selbst gehostet) | `eingabe_build_id`, `eingabe_sha256`, `eingabe_quality_sha256`, `eingabe_version`, `eingabe_kanal`, `eingabe_vorgaenger`, `eingabe_rollback`, `eingabe_ref`, `override_verboten` |
| umgebung | `repository.full_name` = `GITHUB_REPOSITORY`, `private` passend zu `visibility` (öffentlich erlaubt); Environment `release-signing` existiert, hat Pflicht-Reviewer, `can_admins_bypass` nicht `true` (fehlt das Feld: Hinweis „im Portal prüfen“), Bereitstellung nur vom Zweig `main` | `repo_unbekannt`, `umgebung_fehlt`, `umgebung_ungeschuetzt`, `umgebung_admin_bypass`, `umgebung_zweige` |
| qualitaet | Token vorhanden und formal gültig; Manifest; quality.json = Manifest = Eingabe `quality_sha256`; `bestanden:true`, Build-ID, `remote_e2e_fps` | `storage_token_fehlt`, `storage_token_format`, `storage_token`, `storage_nicht_konfiguriert`, `storage_fehlt`, `manifest_ungueltig`, `quality_fehlt`, `quality_abweichung`, `quality_ungueltig`, `storage_nicht_erreichbar`, `storage_weiterleitung` |
| laden | genau ein `unsigned` mit Namen `insight-fernwartung-<BUILD_ID>.exe`, Größe, SHA-256 = Eingabe, noch kein `signed`; Download vollständig und gleich | `asset_fehlt`, `asset_mehrdeutig`, `asset_name`, `asset_groesse`, `digest_abweichung`, `signiert_vorhanden`, `download_abweichung` |
| vorpruefen | SHA-256 der Datei, PE-Struktur, NSIS-firstheader, `ProductName`/`CompanyName` wie `installer.nsi`, `FileVersion` = `BuildId` = Build-ID, noch keine Signatur | `sha256_abweichung`, `kein_pe`, `pe_defekt`, `kein_nsis`, `versionsinfo_fehlt`, `hersteller_abweichung`, `build_id_abweichung`, `bereits_signiert` |
| signieren | Artifact Signing (Action); Exit ≠ 0/2 färbt den Job rot | – |
| nachpruefen | genau ein WIN_CERTIFICATE (PKCS#7) am Dateiende; Inhalt = geprüfte Datei + ≤ 7 Nullbytes + Signatur; Build-ID unverändert; `signtool verify /pa /tw /v` fehlerfrei ohne Warnung; Kette ≥ 2 und Blatt nicht selbst ausgestellt; Aussteller „Microsoft ID Verified CS …“; Inhaber = `ARTIFACT_SIGNING_PUBLISHER`; RFC-3161-Zeitstempel; signtool-Hash = eigener Authenticode-Hash; kein Trockenlauf-Werkzeug; geprüfte Qualität vorhanden und = Eingabe `quality_sha256` | `signatur_fehlt`, `signatur_format`, `zertifikatstabelle_lage`, `inhalt_geaendert`, `signtool_verify`, `nicht_verifiziert`, `selbstsigniert`, `aussteller_abweichung`, `herausgeber_abweichung`, `herausgeber_fehlt`, `zeitstempel_fehlt`, `authenticode_abweichung`, `fake_signtool`, `quality_fehlt`, `quality_abweichung` |
| hochladen | Datei seit Nachprüfung unverändert; PUT ohne Überschreiben | `datei_veraendert`, `storage_konflikt`, `storage_zu_gross`, `storage_abgelehnt`, `storage_token` |
| ablage_pruefen | Manifest `signed` = SHA-256/Größe der geprüften Datei, `unsigned` unverändert, erneuter Download bitgleich | `upload_fehlt`, `upload_digest`, `upload_abweichung`, `ablage_abweichung` |

Installer und Qualitätsnachweis werden **zweimal** geladen und geprüft (Job `vorpruefung` vor der Freigabe, Job
`signieren` danach) – ein nach der Vorprüfung per `replace=1` ausgetauschter Installer scheitert am erwarteten SHA-256
(`digest_abweichung`), ein ersetzter Qualitätsnachweis an der Eingabe `quality_sha256` (`quality_abweichung`, auch wenn
er `bestanden:true` und dieselbe Build-ID trägt), ein gelöschter Build an `storage_fehlt`. Beide Hashes druckt
`vorbereiten.py` aus den lokal geprüften Dateien in den `gh workflow run`-Befehl.

## Sicherheitsregeln des Workflows

Geprüft durch `tools/signing/workflow_check.py` (strenge YAML-Teilmenge, Schema, Pins, feste Schrittfolge) – ohne jeden
Befund, sonst sind die Tests rot.

| Regel | Codes |
|---|---|
| Nur `workflow_dispatch` mit festen Eingaben; kein push, kein Pull-Request | `trigger`, `eingaben` |
| Einziges Secret `secrets.SIGNING_STORAGE_TOKEN`, nur im `env` der sechs Ablage-Schritte (eigene Helfer); nie in Actions, Job-`env`, `with` oder `run` | `secret_referenz`, `secret_ort`, `schritt_env`, `ausdruck_in_run` |
| Azure-Anmeldung nur per OIDC; Kontowerte nur als `${{ vars.NAME }}`; keine Passwort-/Secret-Eingaben der Actions | `action_konfig`, `ausdruck`, `klartext_secret` |
| Rechte je Job exakt: `contents: read`; `actions: read` nur für die Environment-Prüfung; `id-token: write` nur im Job `signieren` | `rechte` |
| Environment `release-signing` nur am Job `signieren`, der auf `tests` und `vorpruefung` wartet | `umgebung`, `needs` |
| Feste Schrittfolge; run-Schritte nur `artifact_signing.py <befehl>`, `az account clear` und die Testbefehle; kein `if`/`continue-on-error` außer Azure-Abmeldung; kein pip | `reihenfolge`, `bedingung`, `schema_schluessel`, `pip` |
| Kein `gh release`, kein Pre-Release, keine Release-API, kein Installer als GitHub-Artefakt (`archive: false`, Installer-Pfad); einziges Artefakt sind die JSON-Nachweise | `release_verboten`, `installer_artefakt` |
| Actions per Commit-SHA mit Tag-Kommentar; `with`-Schlüssel gegen die `action.yml` genau dieses Commits | `pin`, `pin_kommentar`, `action_eingabe`, `action_pflicht` |
| SHA256-Digest, Zeitstempel `http://timestamp.acs.microsoft.com`, Signier-Werkzeugkette ohne Actions-Cache, nur Azure-CLI-Anmeldung | `action_konfig` |
| Nur freigegebene Hosts, keine IP-Literale, keine internen Namen/lokalen Pfade, kein Klartext-Secret, keine Trockenlauf-Variablen | `intern`, `klartext_secret`, `ueberschreibung` |

Gepinnte Stände (am 09.11.2026 gegen die Tags auf GitHub geprüft): `actions/checkout` v7.0.1, `azure/login` v3.1.0,
`azure/artifact-signing-action` v2.0.0, `actions/upload-artifact` v7.0.2. Beim Aktualisieren SHA und Tag im Workflow
**und** im Abzug `ACTIONS` (`tools/signing/workflow_check.py`, inkl. Eingabenliste der neuen `action.yml`) gemeinsam
ändern; die Tests vergleichen Workflow, Abzug und diese Liste. Das Qualitäts-Gate des Cockpits führt eine eigene
Pin-Liste; sie bei derselben Gelegenheit nachziehen.

## Was gegenüber dem bisherigen Pfad entfällt

- **Pre-Release entfällt:** kein `gh release create`/`gh release delete`, kein Tag `installer-unsigniert-…`, keine
  Release-API, kein Server-Digest von Release-Assets. Transport nur noch über die Ablage.
- **Installer-Artefakt entfällt:** kein `actions/upload-artifact` mit `archive: false`, keine REST-Artefakt-ID, kein
  Umweg um `gh run download` (cli/cli#13012). Als GitHub-Artefakt bleiben nur die JSON-Nachweise.
- **Pflicht „Repository privat“ entfällt** (früher `repo_nicht_privat`/`repo_privat_unbekannt`); stattdessen
  `repo_unbekannt` für eine nicht passende Ereignis-Nutzlast.
- **Key-Rotation entfällt:** Weil Kunden-Installer nie in GitHub liegen, muss nach einem Lauf kein Setup-Key widerrufen
  oder rotiert werden (früher Testbuild-Schalter mit Widerruf). Kunden-Installer behalten ihren Schlüssel; der signierte
  Installer braucht ihn.
- **Manuelles Löschen nach Erfolg entfällt:** Die Ablage entfernt Builds nach 7 Tagen; signierte Artefakte werden
  nach einem erfolgreichen Lauf nicht von Hand gelöscht.
- **Privater Code-Checkout entfällt:** Der Job `tests` prüft nur dieses Repository; die Produktqualität kommt als
  Qualitätsnachweis `quality` (`bestanden:true`, `remote_e2e_fps`) aus der Ablage.

## Einrichtung (einmalig) – freigebende Person mit Admin-Rechten

### 0. Voraussetzungen

1. Dieses Repository ist öffentlich (oder privat mit GitHub Enterprise). Environment-Schutz mit Pflicht-Reviewern und
   Zweigregel muss **durchgesetzt** sein, bevor App-Registrierung, Federated Credential und Rolle (Schritte 3–4)
   angelegt werden. Grund: Das Federated Credential vertraut jedem Job mit `environment: release-signing`. Der
   Abbruch `umgebung_ungeschuetzt` in der Vorprüfung ist dabei **keine Sicherheitsgrenze**: Er schützt nur diesen
   Workflow, nicht gegen fremde Workflows.
2. Branch-Schutz für `main` (Pull-Request-Pflicht mit Review, keine Force-Pushes) – in öffentlichen Repositories auf
   jedem Plan verfügbar. Damit kann `sign-cockpit.yml` auf `main` nicht ohne Review geändert werden.
3. Die Ablage ist betriebsbereit (`GET https://cockpit.insight-it.de/api/signing/health` liefert `{"ok":true}`) und
   ein Token für dieses Repository wurde vom Betrieb der Ablage erzeugt (Übergabe nur über den Passwortmanager).
4. Azure-Abonnement mit Owner (oder Contributor + User Access Administrator) für Konto, Profil und Rollenzuweisung.
5. Public Trust ist für Organisationen in der EU verfügbar; die Identitätsvalidierung geht nur im Portal und braucht
   die Rolle **Artifact Signing Identity Verifier**.

### 1. Namensliste (vor dem Anlegen ausfüllen)

Vorschläge dürfen geändert werden; dann denselben Wert in den Befehlen unten anpassen. IDs werden nie von Hand
eingetragen, sondern abgefragt.

| Wert | Vorschlag / fest | Herkunft | GitHub (Environment `release-signing` bzw. Repo) | ✓ |
|---|---|---|---|---|
| Repository | `insight-it-gmbh/cockpit-signing` (Vorschlag) | GitHub | – | ☐ |
| Mandant | – | `az account show --query tenantId` | Variable `AZURE_TENANT_ID` | ☐ |
| Abonnement | – | `az account show --query id` | Variable `AZURE_SUBSCRIPTION_ID` | ☐ |
| Ressourcengruppe | `rg-insight-signing` | frei wählbar | – | ☐ |
| Region / Endpunkt | West Europe → `https://weu.codesigning.azure.net` | Konto-Übersicht „Account URI“; North Europe wäre `https://neu.codesigning.azure.net` | Variable `ARTIFACT_SIGNING_ENDPOINT` | ☐ |
| Artifact-Signing-Konto | `insightitsigning` (3–24 Zeichen, beginnt mit Buchstabe, global eindeutig) | Portal „Artifact Signing Accounts“ | Variable `ARTIFACT_SIGNING_ACCOUNT` | ☐ |
| Identitätsvalidierung | Organisation, **Public**, Insight-IT GmbH | Konto → Identity validations | – | ☐ |
| Zertifikatsprofil | `fernwartungpublic`, Typ **Public Trust** (nicht „Public Trust Test“) | Konto → Certificate profiles | Variable `ARTIFACT_SIGNING_PROFILE` | ☐ |
| Zertifikatsinhaber (CN) | wie im Profil angezeigt, erwartet `Insight-IT GmbH` | Zertifikatsprofil → Subject/Common name | Variable `ARTIFACT_SIGNING_PUBLISHER` | ☐ |
| App-Registrierung | `github-fernwartung-release-signing` (ohne Client-Geheimnis) | Entra ID → App-Registrierungen | – | ☐ |
| Anwendungs-ID | – | `az ad app list --display-name …` | Variable `AZURE_CLIENT_ID` | ☐ |
| Federated Credential | `github-release-signing`, Issuer `https://token.actions.githubusercontent.com`, Audience `api://AzureADTokenExchange` | App → Zertifikate & Geheimnisse → Verbundanmeldeinformationen | – | ☐ |
| Subject | siehe Schritt 3 | GitHub OIDC-Einstellung des Repos | – | ☐ |
| Rolle | **Artifact Signing Certificate Profile Signer**, nur auf dem Zertifikatsprofil | Schritt 3 | – | ☐ |
| GitHub-Environment | `release-signing` (fest, steht im Workflow) | Repo → Settings → Environments | – | ☐ |
| Ablage-Token | vom Betrieb der Ablage | Passwortmanager | **Repo-Secret** `SIGNING_STORAGE_TOKEN` | ☐ |

### 2. Azure-Portal

1. `az provider register --namespace Microsoft.CodeSigning` (einmal je Abonnement, Cloud Shell).
2. Portal → „Artifact Signing Accounts“ → Erstellen: Abonnement, Ressourcengruppe `rg-insight-signing`, Name
   `insightitsigning`, Region West Europe, Tarif nach Bedarf.
3. Konto → Access control (IAM): sich selbst **Artifact Signing Identity Verifier** zuweisen.
4. Konto → Identity validations → New identity → Organization → **Public**; Firmendaten exakt wie im Handelsregister.
   Warten, bis der Status „Completed“ ist.
5. Konto → Certificate profiles → Create → **Public Trust**, Name `fernwartungpublic`, die abgeschlossene Validierung
   wählen. Den angezeigten Common Name notieren (→ `ARTIFACT_SIGNING_PUBLISHER`).

### 3. Azure OIDC: App-Registrierung, Federated Credential und Rolle (Azure Cloud Shell, Bash)

**Voraussetzung: Schritt 0.1 und 0.2 erfüllt.** Vorher weder App noch Federated Credential noch Rolle anlegen. Es gibt
kein Client-Geheimnis: `azure/login` tauscht das kurzlebige OIDC-Token des Jobs `signieren` gegen ein Azure-Token.

Zuerst das Subject-Format des Repositorys bestimmen (lokal mit `gh`, als Repo-Admin):

```bash
REPO="insight-it-gmbh/cockpit-signing"   # Vorschlag aus der Namensliste, anpassen
gh api "repos/$REPO/actions/oidc/customization/sub"
gh api "repos/$REPO" --jq '"OWNER_ID=\(.owner.id) REPO_ID=\(.id)"'
```

- Ohne `"use_immutable_subject": true` gilt das namensbasierte Subject
  `repo:insight-it-gmbh/cockpit-signing:environment:release-signing`.
- Mit Opt-in (empfohlen, schützt vor wiederverwendeten Namen) gilt
  `repo:insight-it-gmbh@${OWNER_ID}/cockpit-signing@${REPO_ID}:environment:release-signing` mit den beiden IDs aus
  dem zweiten Befehl. Opt-in: Repo → Settings → Actions → OIDC bzw. `PUT …/actions/oidc/customization/sub` mit
  `use_immutable_subject`.
- Im Zweifel zeigt der erste Lauf das tatsächliche Subject in der Fehlermeldung von `azure/login` (siehe Fehlerbilder).

**Optional, empfohlen: Subject zusätzlich an diese Workflow-Datei binden (`job_workflow_ref`).** Das Standard-Subject
enthält nur Repository und Environment. Mit einer Subject-Vorlage enthält es zusätzlich Pfad und Ref der
Workflow-Datei; ein anderer Workflow oder derselbe Dateiname auf einem anderen Zweig erhält dann kein Azure-Token.
Laut GitHub-Doku zuerst das passende Federated Credential anlegen, dann die Vorlage setzen (als Repo-Admin):

```bash
printf '{"use_default":false,"include_claim_keys":["repo","context","job_workflow_ref"]}\n' \
  | gh api -X PUT "repos/$REPO/actions/oidc/customization/sub" --input -
gh api "repos/$REPO/actions/oidc/customization/sub"
```

Erwartetes Subject (namensbasiert):
`repo:insight-it-gmbh/cockpit-signing:environment:release-signing:job_workflow_ref:insight-it-gmbh/cockpit-signing/.github/workflows/sign-cockpit.yml@refs/heads/main`.
Maßgeblich ist das Subject, das `azure/login` beim ersten Lauf in der Fehlermeldung nennt – nur dieses übernehmen,
keine IDs oder Pfade raten. Zurück zum Standard mit `{"use_default":true}`.

Dann in der Cloud Shell (Werte anpassen, falls die Namensliste abweicht; für das immutable Subject die Zeile
`SUBJECT=` durch die zweite Form mit den ausgegebenen IDs ersetzen):

```bash
cat > signing-setup.sh <<'EOF'
set -euo pipefail
RG="rg-insight-signing"
KONTO="insightitsigning"
PROFIL="fernwartungpublic"
APP="github-fernwartung-release-signing"
REPO="insight-it-gmbh/cockpit-signing"
SUBJECT="repo:insight-it-gmbh/cockpit-signing:environment:release-signing"

SUB_ID="$(az account show --query id -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"
PROFIL_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.CodeSigning/codeSigningAccounts/${KONTO}/certificateProfiles/${PROFIL}"
az resource show --ids "$PROFIL_ID" -o none   # bricht ab, wenn Konto/Profil nicht existieren
ENDPUNKT="$(az resource show -g "$RG" -n "$KONTO" --resource-type Microsoft.CodeSigning/codeSigningAccounts --query properties.accountUri -o tsv)"

APP_ID="$(az ad app list --display-name "$APP" --query '[0].appId' -o tsv)"
if [ -z "$APP_ID" ]; then
  APP_ID="$(az ad app create --display-name "$APP" --sign-in-audience AzureADMyOrg --query appId -o tsv)"
fi
SP_ID="$(az ad sp list --filter "appId eq '${APP_ID}'" --query '[0].id' -o tsv)"
if [ -z "$SP_ID" ]; then
  SP_ID="$(az ad sp create --id "$APP_ID" --query id -o tsv)"
fi
if [ -z "$(az ad app federated-credential list --id "$APP_ID" --query "[?name=='github-release-signing'].name" -o tsv)" ]; then
  printf '{"name":"github-release-signing","issuer":"https://token.actions.githubusercontent.com","subject":"%s","description":"GitHub Actions %s, Environment release-signing","audiences":["api://AzureADTokenExchange"]}\n' "$SUBJECT" "$REPO" > fic.json
  az ad app federated-credential create --id "$APP_ID" --parameters fic.json -o none
fi
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Artifact Signing Certificate Profile Signer" --scope "$PROFIL_ID" -o none

echo "GitHub-Variablen (lokal mit gh ausführen):"
echo "gh variable set AZURE_CLIENT_ID --env release-signing --repo $REPO --body \"$APP_ID\""
echo "gh variable set AZURE_TENANT_ID --env release-signing --repo $REPO --body \"$TENANT_ID\""
echo "gh variable set AZURE_SUBSCRIPTION_ID --env release-signing --repo $REPO --body \"$SUB_ID\""
echo "gh variable set ARTIFACT_SIGNING_ENDPOINT --env release-signing --repo $REPO --body \"$ENDPUNKT\""
echo "gh variable set ARTIFACT_SIGNING_ACCOUNT --env release-signing --repo $REPO --body \"$KONTO\""
echo "gh variable set ARTIFACT_SIGNING_PROFILE --env release-signing --repo $REPO --body \"$PROFIL\""
EOF
bash signing-setup.sh
```

### 4. Rollenprüfung (Soll/Ist, Cloud Shell)

```bash
APP_ID="$(az ad app list --display-name github-fernwartung-release-signing --query '[0].appId' -o tsv)"
az role assignment list --assignee "$APP_ID" --all --query "[].{rolle:roleDefinitionName, scope:scope}" -o table
az ad app federated-credential list --id "$APP_ID" --query "[].{name:name, issuer:issuer, subject:subject, audiences:audiences}" -o jsonc
az ad app credential list --id "$APP_ID" -o table
```

Soll: genau **eine** Rollenzeile „Artifact Signing Certificate Profile Signer“ mit Scope
`…/codeSigningAccounts/insightitsigning/certificateProfiles/fernwartungpublic`; keine Owner-/Contributor-/Reader-Rolle
auf Abonnement oder Ressourcengruppe; genau ein Federated Credential mit Issuer
`https://token.actions.githubusercontent.com`, dem Subject aus Schritt 3 und Audience `api://AzureADTokenExchange`;
**keine** Client-Geheimnisse oder Zertifikate (letzte Liste leer).

### 5. GitHub-Environment, Variablen und Repo-Secret (lokal mit `gh`, als Repo-Admin)

```bash
REPO="insight-it-gmbh/cockpit-signing"   # anpassen
ICH="$(gh api user --jq .id)"
printf '{"wait_timer":0,"prevent_self_review":false,"reviewers":[{"type":"User","id":%s}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}\n' "$ICH" \
  | gh api -X PUT "repos/$REPO/environments/release-signing" --input -
gh api -X POST "repos/$REPO/environments/release-signing/deployment-branch-policies" -f name=main -f type=branch
gh variable set ARTIFACT_SIGNING_PUBLISHER --env release-signing --repo "$REPO" --body "Insight-IT GmbH"
# Repo-Secret für die Ablage: Wert aus dem Passwortmanager einfügen (Eingabe unsichtbar, nicht im Verlauf)
gh secret set SIGNING_STORAGE_TOKEN --repo "$REPO"
```

Danach die sechs `gh variable set`-Zeilen ausführen, die `signing-setup.sh` ausgegeben hat. Den Wert von
`ARTIFACT_SIGNING_PUBLISHER` an den Common Name aus dem Zertifikatsprofil anpassen, falls er abweicht. Im Browser
(Repo → Settings → Environments → `release-signing`) zusätzlich:

- „Allow administrators to bypass configured protection rules“ **abwählen**. Liefert die GET-Antwort des Environments
  das Feld `can_admins_bypass`, bricht die Vorprüfung bei jedem Wert außer `false` ab (`umgebung_admin_bypass`); fehlt
  es, meldet die Vorprüfung einen Hinweis. Den Haken nach jeder Änderung am Environment **von Hand im Portal**
  kontrollieren.
- Sobald eine zweite Person Reviewer ist: sie eintragen und **Prevent self-review** aktivieren (Vier-Augen; die
  Vorprüfung meldet sonst einen Hinweis).
- Das Ablage-Token ist bewusst ein **Repo-Secret** (die Jobs `vorpruefung` und `signieren` brauchen es; ein
  Environment-Secret stünde der Vorprüfung nicht zur Verfügung). Keine weiteren Secrets anlegen. Das Token rotiert der
  Betrieb der Ablage; danach nur `gh secret set SIGNING_STORAGE_TOKEN` wiederholen.

Kontrolle: `gh variable list --env release-signing --repo "$REPO"` zeigt genau die sieben Variablen `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `ARTIFACT_SIGNING_ENDPOINT`, `ARTIFACT_SIGNING_ACCOUNT`,
`ARTIFACT_SIGNING_PROFILE`, `ARTIFACT_SIGNING_PUBLISHER`; `gh secret list --repo "$REPO"` genau
`SIGNING_STORAGE_TOKEN`.

## Erste Produktivprobe

1. `python3 tools/test_artifact_signing.py` auf `main` grün; `python3 tools/signing/workflow_check.py` ohne Befund.
2. Testbuild für eine Testgruppe bauen (bestehender Ablauf mit `build.sh`) und den Qualitätslauf für genau diese
   Build-ID ausführen; er liefert `quality.json` mit `bestanden: true`, `build_id` und `remote_e2e_fps`.
3. In einer bash das Token aus dem Passwortmanager übernehmen, ohne es in Dateien oder den Verlauf zu schreiben:
   `read -rs SIGNING_STORAGE_TOKEN && export SIGNING_STORAGE_TOKEN`.
4. `python3 tools/signing/vorbereiten.py <installer> --quality <quality.json> --version <version> --erstausrollung
   --repo <owner/repo> > signieren-<BUILD_ID>.sh` – prüft den Build wie die Vorprüfung und quality.json wie der
   Workflow, legt `insight-fernwartung-<BUILD_ID>.unsigniert.exe` und `quality-<BUILD_ID>.json` an und schreibt alle
   folgenden Befehle mit eingesetzten Werten (keine Platzhalter, kein Token) in die Datei. Fehler erscheinen auf dem
   Terminal; die Datei bleibt dann leer.
5. **Standard: als Skript ausführen** – `bash -euo pipefail signieren-<BUILD_ID>.sh` in der Shell aus Schritt 3. Das
   Skript wartet in Block 3 auf die Freigabe im Browser. Bricht es ab, bleibt das Terminal offen, und die Meldung samt
   `ABBRUCH (Exit n)` ist sichtbar. **Interaktiv nur in einer Unter-Shell:** zuerst `bash` eingeben, dann die Blöcke
   der Reihe nach einfügen (Unter-Shell bis Schritt 5 offen lassen). Ein Abbruch beendet dann nur die Unter-Shell;
   direkt in der Terminal-Shell würde `exit 1` das Fenster samt Meldung schließen (Block 0 warnt dann mit
   `WARNUNG: Befehle laufen direkt in der Terminal-Shell`). Jeder Prüf- und Netzbefehl trägt `|| exit 1` bzw.
   `if …; then …; else exit 1; fi` und bricht damit auch **ohne** `set -e` ab (`aufraeumen` läuft per trap und meldet
   `ABBRUCH (Exit n)`).
   Block 0 definiert `ablage_kopf` (Token nur per `printf` über stdin an `curl -H @-`, nie als Argument),
   `loeschen_erlaubt` und `aufraeumen` und setzt `trap aufraeumen EXIT`.
   Block 1: `curl … /api/signing/health`, dann `PUT …/<BUILD_ID>/unsigned` (nur bei Erfolg `HOCHGELADEN`) und
   `PUT …/<BUILD_ID>/quality` mit `X-Artifact-SHA256`, danach `vorbereiten.py manifest-pruefen` (Ablage enthält genau
   diese Hashes, noch kein `signed`).
6. Block 2: `vorbereiten.py laeufe-vorher` merkt die schon vorhandenen Läufe derselben Build-ID (`VORHER`), dann
   `gh workflow run sign-cockpit.yml … -f sha256=… -f quality_sha256=…` (`GESTARTET` schon vor dem Start).
7. Block 3: Job `vorpruefung` abwarten; in der Zusammenfassung Build-ID, SHA-256, Größe und `remote_e2e_fps` mit der
   Ausgabe von Schritt 4 vergleichen. Erst dann im Lauf „Review deployments“ → `release-signing` freigeben. Die Lauf-ID
   bestimmt der gedruckte Block mit `gh run list`, gefiltert auf `sign-cockpit.yml`, `workflow_dispatch`, Zweig `main`
   und den Lauftitel „Installer signieren <BUILD_ID>“. Ausgewertet wird das von `vorbereiten.py lauf-id` **ohne** die
   Läufe aus `VORHER`. GitHub listet neue Läufe verzögert; deshalb gibt es bis zu **6 Versuche** im Abstand von 10 s
   (höchstens etwa eine Minute). Wiederholt wird nur „noch kein neuer Lauf“ (`lauf_fehlt`, Exit 3). Mehr als ein
   neuer Treffer (`lauf_mehrdeutig`) oder ein Fehler bricht sofort ab. Ist nach 6 Versuchen kein Lauf da, bricht der
   Block ebenfalls ab. Dann den Lauf im Browser prüfen und nach „Fortsetzen nach Abbruch“ (Fall A) weitermachen; nie
   „den neuesten“ nehmen.
8. Job `signieren` grün: Zusammenfassungen „Nachprüfung bestanden“ (Inhaber, Aussteller „Microsoft ID Verified CS …“,
   Zeitstempel), „Signierten Installer in der Ablage abgelegt“ und „Ablage geprüft“. Bei Rot: Code nachschlagen
   (Tabelle oben/Fehlerbilder), nichts verwenden; `aufraeumen` löscht den eigenen Upload nur, wenn `gh run view` den
   Lauf als fehlgeschlagen/abgebrochen meldet und kein `signed` vorliegt. Scheitert nur `gh run watch` (Netz, Strg-C,
   Terminal geschlossen), bleibt ein grüner, offener oder nicht abrufbarer Lauf unangetastet; Ergebnis dann nach
   „Fortsetzen nach Abbruch“ (Fall A) laden.
9. Block 4: Nachweise per `gh run download … --name signatur-nachweis-<BUILD_ID>` laden und mit
   `vorbereiten.py nachweis-pruefen` binden (Lauf-URL = dieser Lauf, `sha256_unsigniert` = lokal geprüfter Build,
   `qualitaet.sha256` = lokal geprüfte quality.json, Version/Kanal/Vorgänger dieses Starts, Nachweis `gueltig`, kein Trockenlauf, Ablage-Eintrag vorhanden; sonst
   `nachweis_abweichung` bzw. `nachweis_ungueltig`). Dann `GET …/<BUILD_ID>/signed` per curl und
   `vorbereiten.py ergebnis-pruefen` (bindet den Bericht erneut an beide lokalen SHA-256): Größe und SHA-256 =
   Signaturbericht, NSIS-Kennung, Build-ID, Signatur vorhanden.
   Erst dann entsteht `insight-fernwartung-<BUILD_ID>.exe`. Danach auf einem Windows-Rechner
   `signtool verify /pa /v insight-fernwartung-<BUILD_ID>.exe` und
   `Get-FileHash -Algorithm SHA256 insight-fernwartung-<BUILD_ID>.exe` = `sha256` in `signatur-nachweis.json`.
10. Im Cockpit (Qualität → Releases bzw. `POST /api/quality/releases` mit `release-metadata.json`, danach
    `POST /api/quality/releases/<id>/signature` mit `signatur-nachweis.json`) erfassen; Gate „Signaturnachweis“ muss
    „bestanden“ zeigen.
11. Testinstallation auf einem Testrechner (UAC zeigt „Insight-IT Fernwartung“ und den verifizierten Herausgeber).
    Neue Zertifikate können anfangs SmartScreen-Hinweise auslösen (Reputation), das ist kein Signaturfehler.
12. **Aufräumen – immer, unabhängig vom Ergebnis:** gedruckter letzter Befehl `aufraeumen` (läuft per
    `trap aufraeumen EXIT` sonst automatisch beim Ende der Shell, jeweils genau einmal). Er löscht lokal die
    unsignierte Kopie, die Qualitätskopie und `download.bin`. In der Ablage löscht er (`DELETE …/<BUILD_ID>`, damit
    ein neuer Versuch ohne 409 starten kann) **nur**, wenn `vorbereiten.py loeschen-pruefen` belegt: eigener Upload
    dieses Durchgangs (PUT 201, Manifest-Hashes = lokal geprüft), kein `signed`, und der Lauf wurde nie gestartet oder
    endete laut `gh run view` mit `failure`/`cancelled`/`timed_out`/`startup_failure`. Im Zweifel – Lauf grün, offen,
    nicht bestimmbar oder nicht abrufbar, Manifest nicht lesbar – wird nichts gelöscht; der Build bleibt bis zur
    Retention (7 Tage) liegen; signierte Artefakte nicht von Hand löschen. Endete schon der erste `PUT` mit 409 (Build
    existiert bereits), wird nichts gelöscht – mit und ohne `set -e`.

### Fortsetzen nach Abbruch

Gilt für jeden Abbruch nach dem Upload. Der Fortsetzen-Durchgang löscht in der Ablage **nie** etwas: Block 0 setzt
`HOCHGELADEN=0`, und ohne eigenen `PUT` 201 in diesem Durchgang lässt `aufraeumen` die Ablage unangetastet
(kein `DELETE`). Ein liegen gebliebener Build verschwindet mit der Retention nach 7 Tagen. Fremde oder schon
signierte Artefakte werden nie gelöscht oder ersetzt, auch nicht von Hand.

Vorbereitung für beide Fälle:

1. Neue Unter-Shell öffnen (`bash`) und das Token wie in Schritt 3 übernehmen.
2. `vorbereiten.py` mit **denselben** Dateien und Werten (Version, Kanal, Vorgänger/Erstausrollung) erneut ausführen
   und in `signieren-<BUILD_ID>.sh` schreiben. Das legt die lokalen Kopien neu an, die `aufraeumen` gelöscht hat, und
   druckt dieselben Hashes. Andere Werte führen später zu `nachweis_abweichung`.
3. Block 0 aus der neuen Datei einfügen. Die Blöcke sind an den Kommentaren `# 0)` bis `# 5)` zu erkennen.

**Fall A – Lauf wurde gestartet, aber nicht zu Ende verfolgt.** Beispiele: `lauf_fehlt` nach 6 Versuchen,
`gh run watch` brach ab (Netz, Strg-C), oder das Fenster wurde geschlossen.

1. Im Browser unter Actions → „Fernwartungs-Installer signieren“ den Lauf mit Titel „Installer signieren
   <BUILD_ID>“ suchen. Er muss Event `workflow_dispatch` haben und auf `main` laufen. Es muss der Lauf dieses Starts
   sein, kein älterer derselben Build-ID; im Zweifel nicht fortsetzen.
2. `LAUF=<Lauf-ID>` setzen.
3. Ist der Lauf noch offen: `gh run watch --repo <owner/repo> "$LAUF" --exit-status || exit 1`.
4. Block 4 einfügen, dann Block 5 (`aufraeumen`). Block 4 prüft den Nachweis gegen genau diesen Lauf und beide
   lokalen SHA-256.

Endete der Lauf rot, bricht Block 4 ab. Der Upload bleibt dann bis zur Retention liegen. Ein neuer Versuch derselben
Build-ID geht nach Fall B, sonst mit einem neuen Build.

**Fall B – Ausgang des Uploads oder des Starts unbekannt, neuer Durchgang endet mit 409.** Beispiele: Netzfehler beim
`PUT`, `gh workflow run` scheiterte endgültig, oder der erste `PUT` meldet `storage_konflikt` (HTTP 409).

1. Im Browser prüfen, dass zu dieser Build-ID **kein** Lauf offen ist (wartend, laufend, zur Freigabe) und keiner
   grün endete. Gibt es einen offenen oder grünen Lauf, weiter mit Fall A.
2. Statt der `PUT`-Zeilen nur die letzte Zeile von Block 1 einfügen: `… manifest | … manifest-pruefen …`. Sie gelingt
   nur, wenn die Ablage genau den eigenen, lokal geprüften Installer und Qualitätsnachweis enthält (gleiche SHA-256)
   und noch kein `signed`.
3. Meldet sie `quality_fehlt`, kam nur der Installer an. Dann einmal die `PUT …/quality`-Zeile aus Block 1 einfügen
   und `manifest-pruefen` wiederholen.
4. Dann Block 2, 3, 4 und 5 einfügen. Block 2 merkt ältere Läufe in `VORHER`, sie werden nie verwendet.

Meldet `manifest-pruefen` `ablage_abweichung`, `signiert_vorhanden` oder `asset_fehlt`, liegt ein fremder,
abweichender oder schon signierter Stand in der Ablage. Dann nicht starten und nichts löschen. Ein vorhandenes
Ergebnis über Fall A laden, sonst einen neuen Build erzeugen oder die Retention abwarten.

## Fehlerbilder der ersten Läufe

| Symptom | Ursache | Abhilfe |
|---|---|---|
| `repo_unbekannt` | Ereignis-Nutzlast ohne `repository.private`/`full_name`, fremdes Repository oder widersprüchliche Sichtbarkeit | Lauf im richtigen Repository starten; nichts verwenden |
| `storage_token_fehlt` / `storage_token_format` | Repo-Secret `SIGNING_STORAGE_TOKEN` fehlt, ist leer oder enthält Leerzeichen/Zeilenumbrüche | Secret neu setzen (Schritt 5) |
| `storage_token` (HTTP 401) | Token falsch oder rotiert | aktuelles Token vom Betrieb der Ablage, `gh secret set` |
| `storage_nicht_konfiguriert` (HTTP 503) | Ablage hat serverseitig kein Token | Betrieb der Ablage informieren |
| `storage_nicht_erreichbar` / `storage_weiterleitung` | Netz/TLS gestört bzw. Ablage leitet um | `/api/signing/health` prüfen; Weiterleitungen werden nie verfolgt |
| `storage_fehlt` / `quality_fehlt` / `asset_fehlt` | Build bzw. Datei nicht (mehr) in der Ablage, z. B. Retention nach 7 Tagen | erneut mit `vorbereiten.py` hochladen |
| `quality_ungueltig` | quality.json nicht bestanden, fremde Build-ID oder ohne `remote_e2e_fps` | Qualitätslauf für genau diesen Build wiederholen |
| `quality_abweichung` / `eingabe_quality_sha256` | quality.json in der Ablage ≠ lokal geprüfter Nachweis (Eingabe `quality_sha256`), z. B. per `replace=1` ersetzt | nichts signieren; Nachweis prüfen, mit `vorbereiten.py` neu starten |
| `digest_abweichung` | Erwarteter SHA-256 ≠ Hash in der Ablage (falscher Start oder ausgetauschter Installer) | nichts signieren; Build prüfen, neu hochladen |
| `signiert_vorhanden` / `storage_konflikt` (HTTP 409) | Build wurde schon signiert bzw. `signed` existiert, oder ein früherer Upload desselben Builds liegt noch in der Ablage | vorhandenes Ergebnis verwenden (Fortsetzen, Fall A), eigenen Upload über Fortsetzen, Fall B weiterverwenden oder neuen Build erzeugen; nie überschreiben oder löschen |
| `inkonsistent` (HTTP 409 bei GET/manifest) | Datei und gespeicherter Hash widersprechen sich; die Ablage verweigert die Ausgabe statt falscher Bytes | `?replace=1` mit der korrekten Datei und Hash reparieren; nie mit veraltetem Hash weiterarbeiten |
| `meta_ungueltig` (HTTP 422) | Metadaten enthalten ungültigen Zeitstempel oder ungültige Qualitätswerte | mit korrekter Datei und Metadaten ersetzen; keine Client-Ausnahme einbauen |
| `upload_digest` / `upload_abweichung` | Ablage liefert andere Bytes oder Hashes als geprüft | nichts verwenden; Betrieb der Ablage prüfen lassen, neuer Lauf |
| `umgebung_ungeschuetzt` | keine Pflicht-Reviewer eingetragen | Schritt 5; keine Sicherheitsgrenze gegen fremde Workflows |
| `umgebung_admin_bypass` | Administratoren dürfen die Freigabe umgehen | Schritt 5: Bypass im Portal abwählen |
| `umgebung_fehlt` mit HTTP 403/404 | Environment fehlt oder Token darf es nicht lesen | Environment anlegen; Workflow-Rechte `actions: read` im Job `vorpruefung` prüfen |
| `nachweis_abweichung` | Nachweis aus anderem Lauf, anderem Build bzw. Qualitätsnachweis (SHA-256) oder mit anderen Dispatch-Werten | nichts verwenden; richtigen Lauf prüfen, ggf. neuer Lauf |
| `azure/login`: „No matching federated identity record found for presented assertion subject …“ | Subject im Federated Credential passt nicht | genau das in der Meldung genannte Subject eintragen (Schritt 3) |
| `azure/login`: „No subscriptions found“ | Rollenzuweisung fehlt oder liegt in einem anderen Abonnement | Schritt 3/4 |
| Signierschritt 403 bzw. `SignerSign()` fehlgeschlagen | Endpunkt passt nicht zur Region oder Rolle fehlt | `ARTIFACT_SIGNING_ENDPOINT` = Account URI; Schritt 4 |
| `signtool_verify` mit „not trusted“ | Profil vom Typ „Public Trust Test“ oder Private Trust | Public-Trust-Profil verwenden |
| `herausgeber_abweichung` | `ARTIFACT_SIGNING_PUBLISHER` ≠ Common Name des Zertifikats | Variable auf den gemeldeten Inhaber setzen, wenn er korrekt ist |
| `aussteller_abweichung` | Zertifikat nicht von Artifact Signing | Konto/Profil prüfen |
| `lauf_fehlt` / `lauf_mehrdeutig` | neuer Lauf auch nach 6 Versuchen (≈ 1 min) nicht gelistet bzw. mehrere neue Läufe mit derselben Build-ID | Lauf im Browser prüfen; weiter nach „Fortsetzen nach Abbruch“, Fall A (Block 0 neu, `LAUF=<Lauf-ID>`, Block 4); nie raten |
| `ABBRUCH (Exit n)` bzw. Terminal schließt sich bei einem Fehler | ein Prüf- oder Netzbefehl brach ab; Befehle liefen direkt in der Terminal-Shell statt als Skript bzw. in einer Unter-Shell | als Skript mit `bash -euo pipefail` oder in einer Unter-Shell (`bash`) ausführen; Meldung über `ABBRUCH` lesen; weiter nach „Fortsetzen nach Abbruch“ |
| `HINWEIS [lauf_offen]` / `[lauf_unbekannt]` / `[lauf_nicht_fehlgeschlagen]` / `[signiert_vorhanden]` / `[fremder_upload]` beim Aufräumen | `loeschen-pruefen` konnte keinen eigenen, fehlgeschlagenen Upload ohne `signed` belegen | gewollt: nichts gelöscht, Retention (7 Tage); Lauf im Browser prüfen, Ergebnis ggf. nach „Fortsetzen nach Abbruch“, Fall A laden |
| `sha256_abweichung` beim Laden | Download unvollständig oder verändert | Datei verwerfen, erneut laden |

## Lokaler Trockenlauf und statische Prüfung (ohne Azure, ohne Netz)

```bash
python3 tools/signing/workflow_check.py                          # Schema, Pins, Signaturpfad, Secret/Hosts: ohne Befund
python3 tools/signing/trockenlauf.py --bericht trockenlauf.json   # alle Szenarien mit Fake-signtool/-gh/-Ablage
python3 tools/test_artifact_signing.py                           # Unit-, Vertrags-, Mutations- und Trockenlauf-Tests
```

Der Trockenlauf führt die Jobs `vorpruefung` und `signieren` aus dem Workflow aus: run-Schritte echt, Actions
simuliert – `azure/artifact-signing-action` nach dem Quelltext von v2.0.0 und dem PowerShell-Modul ArtifactSigning
0.1.8 (metadata.json, signtool-Argumente mit Anführungszeichen je Pfad, Windows-Zerlegung). Die Ablage ist ein
Fake mit demselben Vertrag (`tools/signing/fake_storage.py`), eingehängt als injizierter Transport
(`SIGN_STORAGE_FAKE`, auf GitHub-Runnern verboten); der Client-Code ist derselbe wie produktiv. HTTP läuft in keinem
Test über das Netz; die Tests sperren Socket-Verbindungen. Die gedruckten Befehle von `vorbereiten.py` laufen in den
Tests unter `bash -euo pipefail` und ohne `set -e` gegen ein curl-Double auf derselben Fake-Ablage und ein gh-Double. Fake-Signaturen
sind gekennzeichnet; ihr Nachweis ist immer `ungueltig`, und außerhalb des Trockenlaufs bricht die Nachprüfung mit
`fake_signtool` ab.

## Qualitäts-Gates im Cockpit (`/api/quality`, Reiter „Releases“)

Ein Release-Kandidat wird nur freigegeben, wenn **alle** Gates bestanden sind, eine **zweite Person** freigibt und der
angezeigte Gate-Hash unverändert ist. Dieser Workflow liefert dafür `release-metadata.json` und
`signatur-nachweis.json` (Gate „Signaturnachweis“: Status `gueltig`, SHA-256 identisch mit dem Release-Artefakt). Der
Qualitätsnachweis `quality` (u. a. `remote_e2e_fps`, Ziel 13–17 FPS) entsteht im Qualitätslauf des Cockpits und ist
Voraussetzung für den Signaturlauf.

## Grenzen

- Kein Live-Lauf: Azure-Anmeldung, Artifact-Signing-Dienst, echtes signtool, GitHub-API und die Ablage sind nur
  simuliert bzw. statisch geprüft. Der eigene Authenticode-Hash und die Auffüllregel wurden einmalig gegen einen
  öffentlich verfügbaren, signierten NSIS-Installer gegengeprüft.
- Ob `GITHUB_TOKEN` mit `actions: read` die Environment-Regeln lesen darf und ob die `workflow_dispatch`-Nutzlast
  `repository.private`/`full_name` enthält, zeigt erst die Produktivprobe (sonst Abbruch, nie eine Signatur ohne
  Prüfung).
- **Restrisiko Schreibrecht:** Wer Schreibrecht hat, kann `sign-cockpit.yml` ändern (ohne Branch-Schutz direkt auf
  `main`) und Läufe starten; das Repo-Secret steht jedem Workflow dieses Repositorys zur Verfügung. Schreibrecht auf
  dieses Repository deshalb wie Signierrecht und Ablage-Zugriff behandeln; Branch-Schutz (Schritt 0.2) ist Pflicht.
  Auch `job_workflow_ref` bindet nur Pfad und Ref der Workflow-Datei, nicht ihren Inhalt.
- Die Environment-Prüfung der Vorprüfung schützt nur diesen Workflow und ist keine Grenze gegen fremde Workflows;
  diese Grenze bilden Federated Credential (Subject) und der durchgesetzte Environment-Schutz.
- Die Ablage-Prüfung vertraut TLS und dem Token; Integrität sichern zusätzlich der erwartete SHA-256 (Eingabe) und der
  Hash-Vergleich nach dem erneuten Download.
- Die Bindung Installer ↔ Commit ist organisatorisch: geprüft werden SHA-256 und Build-ID, nicht der Quell-Commit des
  Builds. `release-metadata.json` nennt den Commit des Workflow-Laufs (dieses Repositorys).
- Signiert wird nur der äußere Installer; das zur Laufzeit erzeugte `uninstall.exe` und die Skripte im Paket bleiben
  unsigniert.
- Das Cockpit prüft Hash-Gleichheit und Status des Nachweises, nicht die Zertifikatskette selbst; die Kette prüft der
  Workflow.
