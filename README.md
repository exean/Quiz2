# Multiplayer-Quiz

Ein einfaches, mehrspieler-fähiges Quiz mit Node.js + Socket.IO.
Alle Spieler bekommen synchronisiert dieselbe Frage und die nächste Frage erscheint
erst, wenn alle geantwortet haben oder die Zeit abgelaufen ist.

## Funktionen

- Host erstellt ein Spiel und teilt eine 6-stellige Game-PIN
- Spieler joinen vom Smartphone unter `/play.html`
- Multiple-Choice (2–6 Antworten pro Frage) mit individuellem Zeitlimit
- Punkte abhängig von Korrektheit und Antwortzeit
- Live-Leaderboard nach jeder Frage und Endstand am Ende
- Admin-Bereich (`/admin.html`) zum Anlegen/Löschen von Fragen, geschützt per Passwort

## Lokales Ausprobieren

```bash
npm install
npm start
```

Dann `http://localhost:3000` im Browser öffnen.

## Auf Plesk (Node.js) installieren

1. **Domain einrichten** – im Plesk-Panel die Domain anlegen (z. B. `quiz.deine-domain.tld`).
2. **Node.js aktivieren** – auf der Domain unter „Node.js" Node.js einschalten.
3. **Dateien hochladen** – den ganzen Projektordner in das `httpdocs`-Verzeichnis (oder einen Unterordner) hochladen.
4. In den Node.js-Einstellungen folgendes setzen:
   - **Document Root**: das Verzeichnis mit den Projektdateien
   - **Application Mode**: `production`
   - **Application Startup File**: `server.js`
   - **Application URL**: deine Domain
5. **„NPM install"** klicken – Plesk installiert die Abhängigkeiten.
6. **Umgebungsvariablen** setzen (optional aber empfohlen):
   - `ADMIN_PASSWORD` – Passwort für den Admin-Bereich (Standard ist `admin`, unbedingt ändern!)
7. **Anwendung starten / neu starten**.
8. Die Domain im Browser aufrufen.

### Hinweis zu WebSockets

Plesk leitet WebSocket-Anfragen für Node.js-Apps standardmässig korrekt weiter.
Falls es Probleme gibt, prüfe in den Apache/Nginx-Einstellungen der Domain, dass
„WebSocket protocol support" aktiv ist (in den Apache & nginx Settings).
Stelle ausserdem sicher, dass HTTPS aktiv ist – moderne Browser blockieren
gemischte Inhalte bei WebSocket-Verbindungen über `http://`.

## Bedienung

1. **Fragen anlegen** – `/admin.html` öffnen, einloggen, Fragen eingeben.
2. **Spiel starten** – `/host.html` öffnen, „Neues Spiel erstellen" klicken.
   Die angezeigte PIN den Mitspielern geben (z. B. via Beamer).
3. **Spieler beitreten** – die Mitspieler öffnen `/play.html` auf dem Smartphone,
   geben PIN + Name ein.
4. **Quiz starten** – sobald alle in der Lobby sind, klickt der Host „Quiz starten".
5. **Spielen** – jede Frage wird synchron angezeigt. Nach jeder Frage werden Auflösung und
   Punktestand auf allen Geräten gezeigt; mit „Weiter" geht es zur nächsten Frage.
6. **Endstand** – das endgültige Leaderboard wird am Ende angezeigt.

## Dateistruktur

```
server.js              Node.js Backend (Express + Socket.IO)
package.json
data/questions.json    Persistente Frageliste
public/
  index.html           Startseite
  admin.html           Frageverwaltung
  host.html            Host-Bildschirm (PIN, Fragen)
  play.html            Smartphone-View für Spieler
  style.css
```

## Sicherheits-Hinweis

Das Admin-Passwort wird per HTTP-Header übermittelt. Betreibe die Anwendung **nur über HTTPS**.
