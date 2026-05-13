const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const QUESTIONS_FILE = path.join(DATA_DIR, 'questions.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const POINTS_BASE = 1000;

app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function loadQuestions() {
  try {
    return JSON.parse(fs.readFileSync(QUESTIONS_FILE, 'utf8'));
  } catch (err) {
    return [];
  }
}

function saveQuestions(list) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(QUESTIONS_FILE, JSON.stringify(list, null, 2), 'utf8');
}

function newId() {
  return 'q' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function checkAdmin(req, res, next) {
  const header = req.get('x-admin-password');
  if (header !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Falsches Admin-Passwort' });
  }
  next();
}

app.get('/api/questions', checkAdmin, (req, res) => {
  res.json(loadQuestions());
});

app.post('/api/questions', checkAdmin, (req, res) => {
  const { text, answers, correctIndex, timeLimit } = req.body || {};
  if (typeof text !== 'string' || !text.trim()) {
    return res.status(400).json({ error: 'Frage-Text fehlt' });
  }
  if (!Array.isArray(answers) || answers.length < 2 || answers.length > 6) {
    return res.status(400).json({ error: 'Es müssen 2-6 Antworten angegeben werden' });
  }
  if (answers.some((a) => typeof a !== 'string' || !a.trim())) {
    return res.status(400).json({ error: 'Antworten dürfen nicht leer sein' });
  }
  const idx = Number(correctIndex);
  if (!Number.isInteger(idx) || idx < 0 || idx >= answers.length) {
    return res.status(400).json({ error: 'Index der richtigen Antwort ungültig' });
  }
  const time = Number(timeLimit) || 20;
  const question = {
    id: newId(),
    text: text.trim(),
    answers: answers.map((a) => a.trim()),
    correctIndex: idx,
    timeLimit: Math.max(5, Math.min(120, time)),
  };
  const list = loadQuestions();
  list.push(question);
  saveQuestions(list);
  res.json(question);
});

app.delete('/api/questions/:id', checkAdmin, (req, res) => {
  const list = loadQuestions();
  const filtered = list.filter((q) => q.id !== req.params.id);
  if (filtered.length === list.length) {
    return res.status(404).json({ error: 'Frage nicht gefunden' });
  }
  saveQuestions(filtered);
  res.json({ ok: true });
});

/* ----- Game state ----- */

const games = new Map(); // pin -> game

function makePin() {
  let pin;
  do {
    pin = String(Math.floor(100000 + Math.random() * 900000));
  } while (games.has(pin));
  return pin;
}

function publicPlayers(game) {
  return Array.from(game.players.values()).map((p) => ({
    id: p.id,
    name: p.name,
    score: p.score,
  }));
}

function leaderboard(game) {
  return publicPlayers(game).sort((a, b) => b.score - a.score);
}

function broadcastLobby(game) {
  io.to(game.pin).emit('lobby:update', {
    pin: game.pin,
    players: publicPlayers(game),
    totalQuestions: game.questions.length,
  });
}

function startQuestion(game) {
  const q = game.questions[game.currentIndex];
  if (!q) return finishGame(game);

  game.state = 'question';
  game.questionStart = Date.now();
  game.answers = new Map();
  const deadline = game.questionStart + q.timeLimit * 1000;

  io.to(game.pin).emit('question:start', {
    index: game.currentIndex,
    total: game.questions.length,
    text: q.text,
    answers: q.answers,
    timeLimit: q.timeLimit,
    deadline,
  });

  if (game.timer) clearTimeout(game.timer);
  game.timer = setTimeout(() => endQuestion(game, 'timeout'), q.timeLimit * 1000);
}

function endQuestion(game, reason) {
  if (game.state !== 'question') return;
  if (game.timer) {
    clearTimeout(game.timer);
    game.timer = null;
  }
  const q = game.questions[game.currentIndex];
  const totalTime = q.timeLimit * 1000;

  const perPlayer = [];
  for (const player of game.players.values()) {
    const ans = game.answers.get(player.id);
    let correct = false;
    let gained = 0;
    let choice = null;
    if (ans) {
      choice = ans.choice;
      correct = ans.choice === q.correctIndex;
      if (correct) {
        const remaining = Math.max(0, totalTime - (ans.at - game.questionStart));
        const speed = remaining / totalTime;
        gained = Math.round(POINTS_BASE * (0.5 + 0.5 * speed));
        player.score += gained;
      }
    }
    perPlayer.push({ id: player.id, name: player.name, correct, gained, choice });
  }

  const counts = q.answers.map(() => 0);
  for (const ans of game.answers.values()) {
    if (typeof ans.choice === 'number' && counts[ans.choice] !== undefined) {
      counts[ans.choice] += 1;
    }
  }

  game.state = 'review';
  io.to(game.pin).emit('question:end', {
    reason,
    correctIndex: q.correctIndex,
    counts,
    perPlayer,
    leaderboard: leaderboard(game),
    hasNext: game.currentIndex + 1 < game.questions.length,
  });

  for (const player of game.players.values()) {
    const me = perPlayer.find((p) => p.id === player.id);
    io.to(player.socketId).emit('question:result', {
      correct: me ? me.correct : false,
      gained: me ? me.gained : 0,
      score: player.score,
      correctIndex: q.correctIndex,
    });
  }
}

function finishGame(game) {
  game.state = 'finished';
  if (game.timer) {
    clearTimeout(game.timer);
    game.timer = null;
  }
  io.to(game.pin).emit('game:end', {
    leaderboard: leaderboard(game),
  });
}

function disposeGame(game) {
  if (game.timer) clearTimeout(game.timer);
  games.delete(game.pin);
}

/* ----- Socket events ----- */

io.on('connection', (socket) => {
  socket.data.role = null;

  socket.on('host:create', (_payload, cb) => {
    const questions = loadQuestions();
    if (!questions.length) {
      return cb && cb({ error: 'Keine Fragen vorhanden. Bitte zuerst im Admin anlegen.' });
    }
    // shuffle a copy so each game has a fresh order
    const shuffled = questions.slice().sort(() => Math.random() - 0.5);
    const pin = makePin();
    const game = {
      pin,
      hostSocketId: socket.id,
      players: new Map(),
      questions: shuffled,
      currentIndex: -1,
      state: 'lobby',
      answers: new Map(),
      timer: null,
      questionStart: 0,
    };
    games.set(pin, game);
    socket.join(pin);
    socket.data.role = 'host';
    socket.data.pin = pin;
    cb && cb({ pin, totalQuestions: shuffled.length });
    broadcastLobby(game);
  });

  socket.on('player:join', ({ pin, name }, cb) => {
    const game = games.get(String(pin || '').trim());
    if (!game) return cb && cb({ error: 'Game-PIN unbekannt' });
    if (game.state !== 'lobby') return cb && cb({ error: 'Spiel hat bereits begonnen' });
    const clean = String(name || '').trim().slice(0, 20);
    if (!clean) return cb && cb({ error: 'Bitte einen Namen eingeben' });
    for (const p of game.players.values()) {
      if (p.name.toLowerCase() === clean.toLowerCase()) {
        return cb && cb({ error: 'Name ist bereits vergeben' });
      }
    }
    const player = {
      id: socket.id,
      socketId: socket.id,
      name: clean,
      score: 0,
    };
    game.players.set(socket.id, player);
    socket.join(game.pin);
    socket.data.role = 'player';
    socket.data.pin = game.pin;
    socket.data.playerId = player.id;
    cb && cb({ ok: true, pin: game.pin, name: clean });
    broadcastLobby(game);
  });

  socket.on('host:start', (_payload, cb) => {
    const game = games.get(socket.data.pin);
    if (!game || game.hostSocketId !== socket.id) {
      return cb && cb({ error: 'Nur der Host darf starten' });
    }
    if (game.players.size === 0) {
      return cb && cb({ error: 'Mindestens ein Spieler nötig' });
    }
    if (game.state !== 'lobby') {
      return cb && cb({ error: 'Spiel läuft bereits' });
    }
    game.currentIndex = 0;
    startQuestion(game);
    cb && cb({ ok: true });
  });

  socket.on('host:next', (_payload, cb) => {
    const game = games.get(socket.data.pin);
    if (!game || game.hostSocketId !== socket.id) {
      return cb && cb({ error: 'Nur der Host darf weiter' });
    }
    if (game.state !== 'review') return cb && cb({ error: 'Aktuell läuft eine Frage' });
    game.currentIndex += 1;
    if (game.currentIndex >= game.questions.length) {
      finishGame(game);
    } else {
      startQuestion(game);
    }
    cb && cb({ ok: true });
  });

  socket.on('player:answer', ({ choice }, cb) => {
    const game = games.get(socket.data.pin);
    if (!game || game.state !== 'question') return cb && cb({ error: 'Keine aktive Frage' });
    const q = game.questions[game.currentIndex];
    if (!Number.isInteger(choice) || choice < 0 || choice >= q.answers.length) {
      return cb && cb({ error: 'Ungültige Antwort' });
    }
    if (game.answers.has(socket.id)) return cb && cb({ error: 'Schon beantwortet' });
    game.answers.set(socket.id, { choice, at: Date.now() });
    cb && cb({ ok: true });

    io.to(game.hostSocketId).emit('host:answerProgress', {
      answered: game.answers.size,
      total: game.players.size,
    });

    if (game.answers.size >= game.players.size) {
      endQuestion(game, 'all-answered');
    }
  });

  socket.on('disconnect', () => {
    const pin = socket.data.pin;
    if (!pin) return;
    const game = games.get(pin);
    if (!game) return;
    if (socket.data.role === 'host') {
      io.to(pin).emit('game:cancelled', { reason: 'Host hat das Spiel verlassen' });
      disposeGame(game);
      return;
    }
    if (socket.data.role === 'player' && game.players.has(socket.id)) {
      game.players.delete(socket.id);
      game.answers.delete(socket.id);
      broadcastLobby(game);
      if (game.state === 'question' && game.players.size > 0 && game.answers.size >= game.players.size) {
        endQuestion(game, 'all-answered');
      }
      if (game.players.size === 0 && game.state !== 'lobby') {
        // Host bleibt, aber niemand spielt mehr — Spiel pausieren wäre Overkill, einfach Lobby zeigen.
      }
    }
  });
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log('Quiz läuft auf Port ' + PORT);
});
