# Multiplayer-Quiz

Multiplayer-fähiges Quiz mit Node.js + Socket.IO.
Jeder User hat einen eigenen Account und verwaltet seine eigenen Quizzes
(Name, Beschreibung, Fragen). Andere User sehen die Quizzes nicht.

## Funktionen

- **Account-System**: Registrierung per E-Mail + Passwort, Login per Passwort
  **oder Passkey** (WebAuthn, z. B. Touch-ID/Face-ID/Windows-Hello).
- **E-Mail-Verifizierung**: Account erst nach Klick auf Bestätigungslink aktiv.
- **Eigene Quizzes**: jedes Quiz hat Name, Beschreibung und beliebig viele
  Multiple-Choice-Fragen mit Zeitlimit. Nur eigene Quizzes sind sichtbar.
- **Game**: Host startet aus einem Quiz heraus ein Spiel und teilt eine
  6-stellige Game-PIN. Spieler joinen am Smartphone via `/play.html`.
- **Synchronisation**: Die nächste Frage wird erst gezeigt, wenn alle geantwortet
  haben **oder** das Server-Zeitlimit abgelaufen ist.
- **Live-Punkte**: Punkte richten sich nach Korrektheit und Geschwindigkeit;
  Live-Leaderboard nach jeder Frage, finaler Endstand am Schluss.

## Lokales Ausprobieren

```bash
npm install
npm start
```

Dann `http://localhost:3000` im Browser öffnen.

Ohne konfigurierten SMTP-Server gibt der Server den Verify-Link nach der
Registrierung auf der Konsole und auf der Bestätigungsseite aus.

## Auf Plesk (Node.js) installieren

1. **Domain einrichten** – im Plesk-Panel die Domain anlegen (z. B. `quiz.deine-domain.tld`).
2. **HTTPS aktivieren** – ohne HTTPS funktionieren Passkeys & sichere Cookies nicht zuverlässig.
3. **Node.js aktivieren** – auf der Domain unter „Node.js" Node.js (≥ 18) einschalten.
4. **Dateien hochladen** – den Projektordner in `httpdocs` (oder Unterordner) legen.
5. In den Node.js-Einstellungen:
   - **Document Root**: das Verzeichnis mit `server.js`
   - **Application Mode**: `production`
   - **Application Startup File**: `server.js`
6. **„NPM install"** klicken – Plesk installiert die Abhängigkeiten.
7. **Umgebungsvariablen** setzen (Application > Custom environment variables):
   - `RP_NAME` – Anzeigename für Passkeys (optional, Default `Quiz`)
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
     – SMTP-Zugangsdaten (Plesk → Mail-Settings) für E-Mail-Verifizierung
   - `SMTP_SECURE=true` falls Port 465 (sonst STARTTLS auf 587)
8. **Anwendung starten / neu starten**.

### WebSocket-Hinweis

Plesk leitet WebSockets für Node.js standardmäßig korrekt weiter. Falls Probleme
auftreten, in den Apache & nginx Settings der Domain „WebSocket protocol support"
aktivieren.

## Bedienung

1. **Account anlegen** unter `/register.html`, Bestätigungslink in der E-Mail anklicken.
2. **Einloggen** unter `/login.html` mit Passwort oder Passkey.
3. **Dashboard** unter `/dashboard.html`:
   - Quizzes anlegen (Name + Beschreibung)
   - Quizzes bearbeiten (Fragen, Antworten, korrekte Antwort, Zeitlimit)
   - Passkeys hinzufügen / entfernen
   - „Spielen" startet ein Spiel mit dem gewählten Quiz
4. **Spieler** öffnen `/play.html` auf dem Smartphone, geben PIN und Namen ein.
5. **Host** klickt im Lobby-Screen „Quiz starten" sobald alle drin sind.

## Sicherheits-Hinweise

- Passwörter werden mit bcrypt gehasht.
- Sessions per HttpOnly-Cookie (SameSite=Lax). Hinter HTTPS wird das Secure-Flag gesetzt.
- Passkeys (WebAuthn) sind an die Domain gebunden – ein erstellter Passkey
  funktioniert nur auf genau dieser Domain.
- Daten werden als JSON-Dateien in `data/` gespeichert. Mache regelmässig Backups.

## Dateistruktur

```
server.js              Node.js Backend (Express + Socket.IO + Auth + WebAuthn)
package.json
data/                  Persistente Daten (users, quizzes, credentials)
public/
  index.html           Startseite
  login.html           Login (Passwort + Passkey)
  register.html        Registrierung
  dashboard.html       Übersicht eigener Quizzes & Passkey-Verwaltung
  quiz-edit.html       Quiz-Editor (Name, Beschreibung, Fragen)
  host.html            Host-Bildschirm (PIN, Fragen)
  play.html            Smartphone-View für Spieler
  webauthn.js          WebAuthn-Client-Helper
  style.css
```
