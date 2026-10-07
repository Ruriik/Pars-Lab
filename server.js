/**
 * PARS LAB — Real-time classroom quiz engine
 * In-memory state, zero-trust payloads, hardened HTTP + Socket.IO surface.
 */

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT) || 3000;
const TRUST_CLOUDFLARE = process.env.TRUST_CLOUDFLARE === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

const LIMITS = {
  maxRooms: 500,
  maxPlayersPerRoom: 200,
  maxSocketsPerIp: Number(process.env.MAX_SOCKETS_PER_IP) || 150,
  hostGraceMs: 45 * 1000,
  lobbyPlayerGraceMs: 30 * 1000,
  roomIdleMs: 15 * 60 * 1000,
  eventBurst: 25,
  eventWindowMs: 5 * 1000,
  allowedDurations: [10, 20, 30, 45, 60],
  leaderboardAutoSkipMs: 10 * 1000
};

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', TRUST_PROXY ? 1 : false);

const server = http.createServer(app);

/* ───────────────────────── IP resolution ───────────────────────── */

function resolveIp(remoteAddress, headers) {
  if (TRUST_CLOUDFLARE) {
    const cf = headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.length < 64) return cf.trim();
  }
  if (TRUST_PROXY) {
    const xff = headers['x-forwarded-for'];
    if (typeof xff === 'string') {
      const hops = xff.split(',').map((h) => h.trim()).filter(Boolean);
      if (hops.length) return hops[hops.length - 1];
    }
  }
  return remoteAddress || 'unknown';
}

const getClientIp = (req) => resolveIp(req.socket.remoteAddress, req.headers);
const getSocketIp = (socket) => resolveIp(socket.handshake.address, socket.handshake.headers);

/* ───────────────────────── Brute-force ban ───────────────────────── */

const failedPinAttempts = new Map();
const BAN_DURATION_MS = 10 * 60 * 1000;
const WINDOW_DURATION_MS = 60 * 1000;
const MAX_FAILED_ATTEMPTS = 10;

function isIpBanned(ip) {
  const record = failedPinAttempts.get(ip);
  if (!record || !record.bannedUntil) return { banned: false };
  const remaining = record.bannedUntil - Date.now();
  if (remaining > 0) return { banned: true, remainingSec: Math.ceil(remaining / 1000) };
  return { banned: false };
}

function recordFailedPinAttempt(ip) {
  const now = Date.now();
  let record = failedPinAttempts.get(ip);
  if (!record || now - record.windowStart > WINDOW_DURATION_MS) {
    record = { count: 1, windowStart: now, bannedUntil: 0 };
  } else {
    record.count += 1;
    if (record.count >= MAX_FAILED_ATTEMPTS) {
      record.bannedUntil = now + BAN_DURATION_MS;
      console.warn(`[SECURITY] IP ${ip} banned for 10 minutes (PIN brute force).`);
    }
  }
  failedPinAttempts.set(ip, record);
}

const resetFailedPinAttempts = (ip) => failedPinAttempts.delete(ip);

/* ───────────────────────── HTTP hardening ───────────────────────── */

app.use(compression());

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=63072000');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'self'"
    ].join('; ')
  );
  next();
});

const roomCreateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  validate: false,
  message: { success: false, error: 'Çok fazla oda oluşturuldu. Lütfen birkaç dakika sonra tekrar deneyin.' }
});

const pinVerifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  validate: false,
  message: { success: false, error: 'Çok fazla PIN kontrol isteği. Lütfen bekleyin.' }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp,
  validate: false
});

app.use('/api', apiLimiter, express.json({ limit: '2kb' }));

app.get('/mobile.html', (req, res) => res.redirect(301, '/'));
app.get('/vendor/qrcode.js', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
  res.sendFile(path.join(__dirname, 'node_modules', 'qrcode-generator', 'qrcode.js'));
});
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore', index: 'index.html' }));

/* ───────────────────────── Input validation ───────────────────────── */

const isPin = (v) => typeof v === 'string' && /^\d{6}$/.test(v);
const isSafeKey = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(v);
const isToken = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{20,64}$/.test(v);
const own = (obj, key) => obj && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;

function sanitizeNickname(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .normalize('NFC')
    .replace(/[^a-zA-Z0-9_\-\sığüşöçİĞÜŞÖÇ]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 15);
}

function safeTokenEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

const newToken = () => crypto.randomBytes(24).toString('base64url');

/* ───────────────────────── Question bank ───────────────────────── */

let questionDb = { grades: {} };
try {
  questionDb = JSON.parse(fs.readFileSync(path.join(__dirname, 'questions.json'), 'utf8'));
} catch (e) {
  console.error("questions.json yüklenemedi. 'node generate_questions.js' çalıştırdığınıza emin olun.");
}

function getStructureList() {
  const structure = {};
  for (const [gradeId, grade] of Object.entries(questionDb.grades || {})) {
    structure[gradeId] = { name: grade.name, subjects: {} };
    for (const [subId, sub] of Object.entries(grade.subjects || {})) {
      structure[gradeId].subjects[subId] = { name: sub.name, icon: sub.icon || 'book', topics: {} };
      for (const [topId, top] of Object.entries(sub.topics || {})) {
        structure[gradeId].subjects[subId].topics[topId] = { name: top.name, tests: {} };
        for (const [testId, test] of Object.entries(top.tests || {})) {
          structure[gradeId].subjects[subId].topics[topId].tests[testId] = {
            name: test.name,
            questionCount: Array.isArray(test.questions) ? test.questions.length : 0
          };
        }
      }
    }
  }
  return structure;
}
const CATEGORY_STRUCTURE = getStructureList();

function resolveTest(p) {
  if (!p || ![p.gradeId, p.subId, p.topId, p.testId].every(isSafeKey)) return null;
  const grade = own(questionDb.grades, p.gradeId);
  const sub = own(grade && grade.subjects, p.subId);
  const top = own(sub && sub.topics, p.topId);
  const test = own(top && top.tests, p.testId);
  if (!test || !Array.isArray(test.questions) || !test.questions.length) return null;
  return {
    path: { gradeId: p.gradeId, subId: p.subId, topId: p.topId, testId: p.testId },
    name: test.name,
    label: [grade.name, sub.name, top.name, test.name].join(' · '),
    questions: test.questions
  };
}

function firstAvailableTest() {
  for (const [gradeId, grade] of Object.entries(questionDb.grades || {})) {
    for (const [subId, sub] of Object.entries(grade.subjects || {})) {
      for (const [topId, top] of Object.entries(sub.topics || {})) {
        for (const testId of Object.keys(top.tests || {})) {
          const t = resolveTest({ gradeId, subId, topId, testId });
          if (t) return t;
        }
      }
    }
  }
  return null;
}

/* ───────────────────────── Room state ───────────────────────── */

const rooms = new Map();

function generateUniquePin() {
  for (let i = 0; i < 1000; i++) {
    const pin = String(crypto.randomInt(100000, 1000000));
    if (!rooms.has(pin)) return pin;
  }
  return null;
}

const publicPlayers = (room) =>
  Array.from(room.players.values()).map((p) => ({ id: p.id, nickname: p.nickname, score: p.score, online: p.online }));

const onlineCount = (room) => {
  let n = 0;
  for (const p of room.players.values()) if (p.online) n++;
  return n;
};

const answeredCount = (room) => {
  let n = 0;
  for (const p of room.players.values()) if (p.currentAnswer) n++;
  return n;
};

function rankedPlayers(room) {
  return Array.from(room.players.values()).sort((a, b) => b.score - a.score);
}

function getLeaderboard(room, limit = 10) {
  return rankedPlayers(room)
    .slice(0, limit)
    .map((p) => ({ nickname: p.nickname, score: p.score, lastEarned: p.lastEarnedPoints || 0 }));
}

function getDistribution(room) {
  const counts = { A: 0, B: 0, C: 0, D: 0 };
  for (const p of room.players.values()) {
    if (p.currentAnswer && own(counts, p.currentAnswer) !== undefined) counts[p.currentAnswer]++;
  }
  return counts;
}

const toHost = (room, event, payload) => {
  if (room.hostSocketId) io.to(room.hostSocketId).emit(event, payload);
};
const toPlayer = (player, event, payload) => {
  if (player.online && player.socketId) io.to(player.socketId).emit(event, payload);
};

function touch(room) {
  room.lastActivity = Date.now();
}

function clearTimers(room) {
  if (room.timerInterval) clearInterval(room.timerInterval);
  if (room.leaderboardTimeout) clearTimeout(room.leaderboardTimeout);
  room.timerInterval = null;
  room.leaderboardTimeout = null;
}

function closeRoom(room, message) {
  clearTimers(room);
  if (room.hostGraceTimeout) clearTimeout(room.hostGraceTimeout);
  for (const p of room.players.values()) if (p.graceTimeout) clearTimeout(p.graceTimeout);
  io.to(room.pin).emit('room_closed', { message });
  io.in(room.pin).socketsLeave(room.pin);
  rooms.delete(room.pin);
}

function pushPlayerList(room) {
  toHost(room, 'player_list_updated', { count: room.players.size, online: onlineCount(room), players: publicPlayers(room) });
}

function finishQuestion(room) {
  if (!room || room.state !== 'QUESTION') return;
  clearTimers(room);
  room.state = 'RESULT';
  room.remainingSeconds = 0;

  const qObj = room.questions[room.currentQuestionIndex];
  const maxMs = room.questionDuration * 1000;

  for (const p of room.players.values()) {
    if (p.currentAnswer && p.currentAnswer === qObj.correct) {
      const speed = Math.max(0, 1 - p.responseTimeMs / maxMs);
      const earned = Math.round(500 + 500 * speed);
      p.score += earned;
      p.lastEarnedPoints = earned;
      p.streak = (p.streak || 0) + 1;
    } else {
      p.lastEarnedPoints = 0;
      p.streak = 0;
    }
  }

  const ranked = rankedPlayers(room);
  const rankMap = new Map(ranked.map((p, i) => [p.id, i + 1]));

  toHost(room, 'host_question_result', {
    correct: qObj.correct,
    distribution: getDistribution(room),
    totalAnswered: answeredCount(room),
    totalPlayers: room.players.size,
    isLast: room.currentQuestionIndex + 1 >= room.questions.length,
    leaderboard: getLeaderboard(room, 5)
  });

  for (const p of room.players.values()) {
    toPlayer(p, 'player_question_result', playerResultPayload(room, p, rankMap.get(p.id) || 1));
  }
}

function playerResultPayload(room, p, rank) {
  const qObj = room.questions[room.currentQuestionIndex];
  return {
    action: 'show_result',
    isCorrect: !!p.currentAnswer && p.currentAnswer === qObj.correct,
    selectedAnswer: p.currentAnswer || null,
    earnedPoints: p.lastEarnedPoints || 0,
    totalScore: p.score,
    streak: p.streak || 0,
    rank,
    totalPlayers: room.players.size
  };
}

function gameOver(room) {
  clearTimers(room);
  room.state = 'PODIUM';
  touch(room);
  const leaderboard = getLeaderboard(room, 10);
  toHost(room, 'host_game_over', { podium: leaderboard.slice(0, 3), leaderboard, totalPlayers: room.players.size });
  rankedPlayers(room).forEach((p, i) => {
    toPlayer(p, 'player_game_over', { rank: i + 1, totalScore: p.score, totalPlayers: room.players.size });
  });
}

function startNextQuestion(room) {
  clearTimers(room);
  touch(room);
  room.currentQuestionIndex += 1;

  if (room.currentQuestionIndex >= room.questions.length) {
    gameOver(room);
    return;
  }

  const idx = room.currentQuestionIndex;
  const qObj = room.questions[idx];
  room.state = 'QUESTION';
  room.questionStartTime = Date.now();
  room.questionDuration = room.settings.questionDuration;
  room.remainingSeconds = room.questionDuration;

  for (const p of room.players.values()) {
    p.currentAnswer = null;
    p.responseTimeMs = 0;
    p.lastEarnedPoints = 0;
  }

  toHost(room, 'host_show_question', {
    questionIndex: idx,
    totalQuestions: room.questions.length,
    categoryName: room.testName,
    q: qObj.q,
    options: qObj.options,
    duration: room.questionDuration,
    totalPlayers: room.players.size,
    answeredCount: 0
  });

  for (const p of room.players.values()) {
    toPlayer(p, 'player_show_buttons', {
      action: 'show_buttons',
      questionIndex: idx + 1,
      totalQuestions: room.questions.length,
      duration: room.questionDuration
    });
  }

  room.timerInterval = setInterval(() => {
    room.remainingSeconds -= 1;
    io.to(room.pin).emit('timer_tick', { remainingSeconds: Math.max(0, room.remainingSeconds) });
    if (room.remainingSeconds <= 0) finishQuestion(room);
  }, 1000);
}

function showLeaderboard(room) {
  room.state = 'LEADERBOARD';
  touch(room);
  toHost(room, 'host_leaderboard_view', {
    leaderboard: getLeaderboard(room, 5),
    questionIndex: room.currentQuestionIndex + 1,
    totalQuestions: room.questions.length,
    categoryName: room.testName,
    autoSkipMs: room.settings.autoSkipLeaderboard ? LIMITS.leaderboardAutoSkipMs : 0
  });
  rankedPlayers(room).forEach((p, i) => {
    toPlayer(p, 'player_leaderboard_view', { rank: i + 1, score: p.score, totalPlayers: room.players.size });
  });

  if (room.settings.autoSkipLeaderboard) {
    room.leaderboardTimeout = setTimeout(() => {
      if (rooms.has(room.pin) && room.state === 'LEADERBOARD') startNextQuestion(room);
    }, LIMITS.leaderboardAutoSkipMs);
  }
}

/* ───────────────────────── REST API ───────────────────────── */

app.get('/api/categories', (req, res) => {
  res.json({ success: true, categories: CATEGORY_STRUCTURE });
});

app.post('/api/rooms', roomCreateLimiter, (req, res) => {
  const ip = getClientIp(req);
  const ban = isIpBanned(ip);
  if (ban.banned) {
    return res.status(429).json({ success: false, error: `IP adresiniz engellendi. Kalan süre: ${ban.remainingSec} saniye.` });
  }
  if (rooms.size >= LIMITS.maxRooms) {
    return res.status(503).json({ success: false, error: 'Sunucu kapasitesi dolu. Lütfen daha sonra deneyin.' });
  }

  const pin = generateUniquePin();
  const test = firstAvailableTest();
  if (!pin || !test) {
    return res.status(500).json({ success: false, error: 'Oda oluşturulamadı.' });
  }

  const hostToken = newToken();
  rooms.set(pin, {
    pin,
    hostToken,
    hostSocketId: null,
    hostGraceTimeout: null,
    state: 'LOBBY',
    selectedPath: test.path,
    testName: test.label,
    questions: test.questions,
    settings: { questionDuration: 20, autoFinish: true, autoSkipLeaderboard: false },
    createdAt: Date.now(),
    lastActivity: Date.now(),
    currentQuestionIndex: -1,
    questionStartTime: 0,
    questionDuration: 20,
    remainingSeconds: 0,
    timerInterval: null,
    leaderboardTimeout: null,
    players: new Map(),
    nicknames: new Set(),
    revokedTokens: new Set()
  });

  console.log(`[ROOM CREATED] PIN ${pin}`);
  res.setHeader('Cache-Control', 'no-store');
  res.json({ success: true, pin, hostToken, selectedPath: test.path });
});

app.post('/api/check-pin', pinVerifyLimiter, (req, res) => {
  const ip = getClientIp(req);
  const ban = isIpBanned(ip);
  if (ban.banned) {
    return res.status(429).json({
      success: false,
      banned: true,
      error: `Güvenlik: Çok fazla hatalı deneme. Kalan: ${ban.remainingSec} sn.`
    });
  }

  const pin = req.body && req.body.pin;
  if (!isPin(pin)) {
    recordFailedPinAttempt(ip);
    return res.status(400).json({ success: false, error: 'Geçersiz 6 haneli PIN.' });
  }

  const room = rooms.get(pin);
  if (!room) {
    recordFailedPinAttempt(ip);
    return res.status(404).json({ success: false, error: 'Oda bulunamadı. Lütfen PIN kodunu kontrol edin.' });
  }
  if (room.state !== 'LOBBY') {
    return res.status(403).json({ success: false, error: 'Oyun zaten başlamış veya kapalı.' });
  }

  resetFailedPinAttempts(ip);
  res.json({ success: true, state: room.state });
});

app.use('/api', (req, res) => res.status(404).json({ success: false, error: 'Bulunamadı.' }));

app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large')) {
    return res.status(400).json({ success: false, error: 'Geçersiz istek.' });
  }
  console.error('[HTTP ERROR]', err && err.message);
  res.status(500).json({ success: false, error: 'Sunucu hatası.' });
});

/* ───────────────────────── Socket.IO ───────────────────────── */

function isOriginAllowed(origin, host) {
  if (!origin) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

const io = new Server(server, {
  maxHttpBufferSize: 4 * 1024,
  pingInterval: 20000,
  pingTimeout: 20000,
  connectTimeout: 15000,
  serveClient: true,
  allowRequest: (req, callback) => {
    callback(null, isOriginAllowed(req.headers.origin, req.headers.host));
  }
});

const socketsPerIp = new Map();

io.use((socket, next) => {
  const ip = getSocketIp(socket);
  const ban = isIpBanned(ip);
  if (ban.banned) return next(new Error(`IP engellendi. Kalan süre: ${ban.remainingSec} saniye.`));
  const count = socketsPerIp.get(ip) || 0;
  if (count >= LIMITS.maxSocketsPerIp) return next(new Error('Bu ağdan çok fazla bağlantı var.'));
  socketsPerIp.set(ip, count + 1);
  socket.data.ip = ip;
  next();
});

io.on('connection', (socket) => {
  const clientIp = socket.data.ip;
  const bucket = { tokens: LIMITS.eventBurst, last: Date.now() };
  const throttles = new Map();

  const throttled = (key, ms) => {
    const now = Date.now();
    if (now - (throttles.get(key) || 0) < ms) return true;
    throttles.set(key, now);
    return false;
  };

  socket.use((packet, next) => {
    const now = Date.now();
    const refill = ((now - bucket.last) / LIMITS.eventWindowMs) * LIMITS.eventBurst;
    bucket.tokens = Math.min(LIMITS.eventBurst, bucket.tokens + refill);
    bucket.last = now;
    if (bucket.tokens < 1) {
      console.warn(`[SECURITY] Event flood from ${clientIp}, disconnecting.`);
      socket.disconnect(true);
      return;
    }
    bucket.tokens -= 1;
    next();
  });

  const on = (event, handler) => {
    socket.on(event, (data) => {
      try {
        handler(data && typeof data === 'object' ? data : {});
      } catch (err) {
        console.error(`[SOCKET ERROR] ${event}:`, err && err.message);
      }
    });
  };

  const authError = (message) => socket.emit('auth_error', { message });

  function validateHost(pin) {
    const room = isPin(pin) ? rooms.get(pin) : null;
    if (!room || socket.data.role !== 'host' || socket.data.pin !== pin || room.hostSocketId !== socket.id) {
      socket.emit('error_msg', 'Erişim reddedildi: Bu işlemi yalnızca Host gerçekleştirebilir.');
      return null;
    }
    touch(room);
    return room;
  }

  /* --- Host attach / reattach (requires secret host token) --- */
  on('host_join_room', (data) => {
    if (socket.data.role) return;
    const room = isPin(data.pin) ? rooms.get(data.pin) : null;
    if (!room || !safeTokenEqual(data.hostToken, room.hostToken)) {
      recordFailedPinAttempt(clientIp);
      return authError('Host doğrulaması başarısız.');
    }

    if (room.hostSocketId && room.hostSocketId !== socket.id) {
      const prev = io.sockets.sockets.get(room.hostSocketId);
      if (prev) {
        prev.data.role = null;
        prev.emit('room_closed', { message: 'Panel başka bir sekmede açıldı.' });
        prev.disconnect(true);
      }
    }
    if (room.hostGraceTimeout) {
      clearTimeout(room.hostGraceTimeout);
      room.hostGraceTimeout = null;
    }

    room.hostSocketId = socket.id;
    socket.data.role = 'host';
    socket.data.pin = room.pin;
    socket.join(room.pin);
    touch(room);
    io.to(room.pin).except(socket.id).emit('host_status', { online: true });

    socket.emit('host_connected', {
      pin: room.pin,
      state: room.state,
      categories: CATEGORY_STRUCTURE,
      selectedPath: room.selectedPath,
      categoryName: room.testName,
      questionCount: room.questions.length,
      settings: room.settings,
      players: publicPlayers(room)
    });

    if (room.state === 'QUESTION') {
      const qObj = room.questions[room.currentQuestionIndex];
      socket.emit('host_show_question', {
        questionIndex: room.currentQuestionIndex,
        totalQuestions: room.questions.length,
        categoryName: room.testName,
        q: qObj.q,
        options: qObj.options,
        duration: room.questionDuration,
        remaining: room.remainingSeconds,
        totalPlayers: room.players.size,
        answeredCount: answeredCount(room)
      });
    }
  });

  /* --- Player join --- */
  on('player_join_room', (data) => {
    if (socket.data.role || throttled('join', 500)) return;

    const ban = isIpBanned(clientIp);
    if (ban.banned) return authError(`IP engellendi. Kalan: ${ban.remainingSec} sn.`);

    if (!isPin(data.pin)) {
      recordFailedPinAttempt(clientIp);
      return authError('PIN 6 haneli rakamlardan oluşmalıdır.');
    }
    const room = rooms.get(data.pin);
    if (!room) {
      recordFailedPinAttempt(clientIp);
      return authError('Oda bulunamadı. Lütfen PIN kodunu kontrol edin.');
    }
    if (room.state !== 'LOBBY') return authError('Oyun zaten başlamış veya kapalı.');
    if (room.players.size >= LIMITS.maxPlayersPerRoom) return authError('Oda dolu.');

    const nickname = sanitizeNickname(data.nickname);
    if (nickname.length < 2) return authError('Geçersiz takma ad (en az 2 karakter, özel karakter içermez).');
    const nickKey = nickname.toLocaleLowerCase('tr');
    if (room.nicknames.has(nickKey)) return authError('Bu takma ad odada zaten kullanılıyor.');

    resetFailedPinAttempts(clientIp);

    const player = {
      id: crypto.randomBytes(8).toString('hex'),
      token: newToken(),
      socketId: socket.id,
      nickname,
      nickKey,
      online: true,
      graceTimeout: null,
      score: 0,
      streak: 0,
      currentAnswer: null,
      responseTimeMs: 0,
      lastEarnedPoints: 0
    };
    room.players.set(player.id, player);
    room.nicknames.add(nickKey);
    socket.data.role = 'player';
    socket.data.pin = room.pin;
    socket.data.playerId = player.id;
    socket.join(room.pin);
    touch(room);

    socket.emit('player_joined', { pin: room.pin, nickname, state: room.state, sessionToken: player.token });
    pushPlayerList(room);
  });

  /* --- Player resume after network drop --- */
  on('player_rejoin', (data) => {
    if (socket.data.role || throttled('rejoin', 1000)) return;
    const room = isPin(data.pin) ? rooms.get(data.pin) : null;
    if (!room || !isToken(data.sessionToken) || room.revokedTokens.has(data.sessionToken)) {
      return socket.emit('rejoin_failed', { message: 'Oturum bulunamadı.' });
    }
    const player = Array.from(room.players.values()).find((p) => safeTokenEqual(p.token, data.sessionToken));
    if (!player) return socket.emit('rejoin_failed', { message: 'Oturum süresi doldu.' });

    if (player.graceTimeout) {
      clearTimeout(player.graceTimeout);
      player.graceTimeout = null;
    }
    const prev = player.socketId && io.sockets.sockets.get(player.socketId);
    if (prev && prev.id !== socket.id) {
      prev.data.role = null;
      prev.disconnect(true);
    }

    player.socketId = socket.id;
    player.online = true;
    socket.data.role = 'player';
    socket.data.pin = room.pin;
    socket.data.playerId = player.id;
    socket.join(room.pin);

    socket.emit('player_joined', {
      pin: room.pin,
      nickname: player.nickname,
      state: room.state,
      sessionToken: player.token,
      resumed: true,
      totalScore: player.score
    });
    if (!room.hostSocketId) socket.emit('host_status', { online: false });

    const rank = rankedPlayers(room).findIndex((p) => p.id === player.id) + 1;
    if (room.state === 'QUESTION') {
      if (player.currentAnswer) {
        socket.emit('player_answer_received', { selectedAnswer: player.currentAnswer });
      } else {
        socket.emit('player_show_buttons', {
          action: 'show_buttons',
          questionIndex: room.currentQuestionIndex + 1,
          totalQuestions: room.questions.length,
          duration: room.remainingSeconds
        });
      }
    } else if (room.state === 'RESULT') {
      socket.emit('player_question_result', playerResultPayload(room, player, rank));
    } else if (room.state === 'LEADERBOARD') {
      socket.emit('player_leaderboard_view', { rank, score: player.score, totalPlayers: room.players.size });
    } else if (room.state === 'PODIUM') {
      socket.emit('player_game_over', { rank, totalScore: player.score, totalPlayers: room.players.size });
    }
    pushPlayerList(room);
  });

  /* --- Host commands --- */
  on('host_kick_player', (data) => {
    const room = validateHost(data.pin);
    if (!room || typeof data.playerId !== 'string') return;
    const player = room.players.get(data.playerId);
    if (!player) return;

    if (player.graceTimeout) clearTimeout(player.graceTimeout);
    room.players.delete(player.id);
    room.nicknames.delete(player.nickKey);
    room.revokedTokens.add(player.token);

    const ps = player.socketId && io.sockets.sockets.get(player.socketId);
    if (ps) {
      ps.emit('room_closed', { message: 'Eğitmen tarafından odadan çıkarıldın.', kicked: true });
      ps.data.role = null;
      ps.leave(room.pin);
      setTimeout(() => ps.disconnect(true), 100);
    }
    pushPlayerList(room);
  });

  on('host_select_category', (data) => {
    const room = validateHost(data.pin);
    if (!room) return;
    if (room.state !== 'LOBBY') return socket.emit('error_msg', 'Test yalnızca lobi aşamasında değiştirilebilir.');

    const test = resolveTest(data.selectedPath);
    if (!test) return socket.emit('error_msg', 'Seçilen test bulunamadı veya boş.');

    const s = data.settings && typeof data.settings === 'object' ? data.settings : {};
    const duration = Number.parseInt(s.questionDuration, 10);

    room.selectedPath = test.path;
    room.testName = test.label;
    room.questions = test.questions;
    room.settings = {
      questionDuration: LIMITS.allowedDurations.includes(duration) ? duration : 20,
      autoFinish: s.autoFinish !== false,
      autoSkipLeaderboard: s.autoSkipLeaderboard === true
    };

    socket.emit('host_category_updated', {
      selectedPath: test.path,
      categoryName: test.label,
      questionCount: test.questions.length,
      settings: room.settings
    });
  });

  on('host_next_question', (data) => {
    const room = validateHost(data.pin);
    if (!room || throttled('next', 800)) return;
    if (!['LOBBY', 'RESULT', 'LEADERBOARD'].includes(room.state)) return;
    if (room.state === 'LOBBY' && room.players.size === 0) {
      return socket.emit('error_msg', 'Oyunu başlatmak için en az bir öğrenci gerekli.');
    }
    startNextQuestion(room);
  });

  on('host_skip_timer', (data) => {
    const room = validateHost(data.pin);
    if (!room || room.state !== 'QUESTION') return;
    io.to(room.pin).emit('timer_tick', { remainingSeconds: 0 });
    finishQuestion(room);
  });

  on('host_show_leaderboard', (data) => {
    const room = validateHost(data.pin);
    if (!room || room.state !== 'RESULT' || throttled('board', 500)) return;
    showLeaderboard(room);
  });

  on('host_end_game', (data) => {
    const room = validateHost(data.pin);
    if (!room || room.state === 'PODIUM') return;
    gameOver(room);
  });

  /* --- Player answer --- */
  on('player_submit_answer', (data) => {
    if (socket.data.role !== 'player' || throttled('answer', 300)) return;
    const answer = typeof data.answer === 'string' ? data.answer.toUpperCase() : '';
    if (!['A', 'B', 'C', 'D'].includes(answer)) return;

    const room = rooms.get(socket.data.pin);
    if (!room || room.state !== 'QUESTION' || data.pin !== room.pin) return;
    const player = room.players.get(socket.data.playerId);
    if (!player || player.currentAnswer) return;

    const elapsed = Math.max(0, Date.now() - room.questionStartTime);
    if (elapsed > room.questionDuration * 1000 + 500) return;

    player.currentAnswer = answer;
    player.responseTimeMs = elapsed;
    socket.emit('player_answer_received', { selectedAnswer: answer });

    const answered = answeredCount(room);
    toHost(room, 'host_answer_update', { answeredCount: answered, totalPlayers: room.players.size });

    if (room.settings.autoFinish && answered >= onlineCount(room)) {
      io.to(room.pin).emit('timer_tick', { remainingSeconds: 0 });
      finishQuestion(room);
    }
  });

  /* --- Disconnect --- */
  socket.on('disconnect', () => {
    const left = (socketsPerIp.get(clientIp) || 1) - 1;
    if (left <= 0) socketsPerIp.delete(clientIp);
    else socketsPerIp.set(clientIp, left);

    const room = socket.data.pin && rooms.get(socket.data.pin);
    if (!room) return;

    if (socket.data.role === 'host' && room.hostSocketId === socket.id) {
      room.hostSocketId = null;
      io.to(room.pin).emit('host_status', { online: false });
      room.hostGraceTimeout = setTimeout(() => {
        if (rooms.has(room.pin) && !room.hostSocketId) {
          closeRoom(room, 'Eğitmen bağlantısı kesildi. Oyun sonlandırıldı.');
        }
      }, LIMITS.hostGraceMs);
      return;
    }

    if (socket.data.role === 'player') {
      const player = room.players.get(socket.data.playerId);
      if (!player || player.socketId !== socket.id) return;
      player.online = false;
      player.socketId = null;

      if (room.state === 'LOBBY') {
        player.graceTimeout = setTimeout(() => {
          if (!player.online && rooms.has(room.pin) && room.state === 'LOBBY') {
            room.players.delete(player.id);
            room.nicknames.delete(player.nickKey);
            pushPlayerList(room);
          }
        }, LIMITS.lobbyPlayerGraceMs);
      }
      pushPlayerList(room);

      if (room.state === 'QUESTION') {
        toHost(room, 'host_answer_update', { answeredCount: answeredCount(room), totalPlayers: room.players.size });
      }
    }
  });
});

/* ───────────────────────── Housekeeping ───────────────────────── */

setInterval(() => {
  const now = Date.now();
  for (const room of rooms.values()) {
    if (now - room.lastActivity > LIMITS.roomIdleMs) {
      closeRoom(room, 'Oda uzun süre hareketsiz kaldığı için kapatıldı.');
    }
  }
  for (const [ip, record] of failedPinAttempts.entries()) {
    if ((!record.bannedUntil || record.bannedUntil <= now) && now - record.windowStart > WINDOW_DURATION_MS) {
      failedPinAttempts.delete(ip);
    }
  }
}, 60 * 1000).unref();

process.on('unhandledRejection', (err) => console.error('[UNHANDLED]', err));

server.listen(PORT, () => {
  console.log(`PARS LAB server on :${PORT}  —  host: /host.html  player: /`);
});
