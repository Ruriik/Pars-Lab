/**
 * PARS LAB - Retro 8-Bit Cyber Real-Time Quiz Engine
 * Zero Trust Architecture, In-Memory State, Cloudflare Proxy Aware, OWASP Security Hardened
 */

const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const PORT = process.env.PORT || 3000;

// 1. CLOUDFLARE IP RESOLUTION & TRUST PROXY
app.set('trust proxy', true);

function getClientIp(req) {
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp && typeof cfIp === 'string') return cfIp.trim();
  const xForwarded = req.headers['x-forwarded-for'];
  if (xForwarded && typeof xForwarded === 'string') return xForwarded.split(',')[0].trim();
  return req.socket.remoteAddress || req.ip || '127.0.0.1';
}

function getSocketIp(socket) {
  const headers = socket.handshake.headers;
  const cfIp = headers['cf-connecting-ip'];
  if (cfIp && typeof cfIp === 'string') return cfIp.trim();
  const xForwarded = headers['x-forwarded-for'];
  if (xForwarded && typeof xForwarded === 'string') return xForwarded.split(',')[0].trim();
  return socket.handshake.address || '127.0.0.1';
}

// 2. SECURITY: FAILED PIN ATTEMPT TRACKER & TEMPORARY BAN SYSTEM
// Ban IPs temporarily after 10 failed PIN attempts in 1 minute
const failedPinAttempts = new Map(); // ip -> { count: number, windowStart: number, bannedUntil: number }
const BAN_DURATION_MS = 10 * 60 * 1000; // 10 minutes ban
const WINDOW_DURATION_MS = 60 * 1000; // 1 minute tracking window
const MAX_FAILED_ATTEMPTS = 10;

function isIpBanned(ip) {
  const record = failedPinAttempts.get(ip);
  if (!record) return { banned: false };
  const now = Date.now();
  if (record.bannedUntil && record.bannedUntil > now) {
    const remainingSec = Math.ceil((record.bannedUntil - now) / 1000);
    return { banned: true, remainingSec };
  }
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
      console.warn(`[SECURITY ALERT] IP ${ip} has been temporarily banned for 10 minutes due to 10 failed PIN attempts.`);
    }
  }
  failedPinAttempts.set(ip, record);
}

function resetFailedPinAttempts(ip) {
  failedPinAttempts.delete(ip);
}

// Clean up old IP ban records periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of failedPinAttempts.entries()) {
    if (record.bannedUntil && record.bannedUntil <= now && now - record.windowStart > WINDOW_DURATION_MS) {
      failedPinAttempts.delete(ip);
    }
  }
}, 5 * 60 * 1000);

// 3. RATE LIMITERS (OWASP DDOS & BRUTE FORCE PROTECTION)
const roomCreateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  validate: { trustProxy: false, xForwardedForHeader: false },
  message: { success: false, error: 'Çok fazla oda oluşturuldu. Lütfen birkaç dakika sonra tekrar deneyin.' }
});

const pinVerifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  validate: { trustProxy: false, xForwardedForHeader: false },
  message: { success: false, error: 'Çok fazla PIN kontrol isteği. Lütfen bekleyin.' }
});

const fs = require('fs');
const compression = require('compression');

// Enable GZIP Compression for all HTTP responses
app.use(compression());

// Middleware for parsing JSON & serving static files
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 4. XSS PROTECTION & INPUT SANITIZATION
function sanitizeString(str, maxLen = 30) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/<[^>]*>?/gm, '') // Strip HTML tags
    .replace(/[&<>"'/]/g, (s) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;'
    }[s] || ''))
    .trim()
    .slice(0, maxLen);
}

function sanitizeNickname(rawName) {
  if (typeof rawName !== 'string') return '';
  let cleaned = rawName.replace(/<[^>]*>?/gm, '').trim();
  cleaned = cleaned.replace(/[^a-zA-Z0-9_\-\sığüşöçİĞÜŞÖÇ]/g, '');
  return cleaned.trim().slice(0, 15);
}

// Load Hierarchical Questions from JSON
let questionDb = { grades: {} };
try {
  questionDb = JSON.parse(fs.readFileSync(path.join(__dirname, 'questions.json'), 'utf8'));
} catch (e) {
  console.error("questions.json yüklenemedi. 'node generate_questions.js' çalıştırdığınıza emin olun.");
}

// 5. MODULAR QUESTION PACKS (Maarif Modeli & EBA Uyumlu)
// This endpoint sends the nested structure (Grades -> Subjects -> Topics -> Tests) to the Host UI.
// We strip the actual "questions" array to save bandwidth.
function getStructureList() {
  const structure = {};
  for (const [gradeId, grade] of Object.entries(questionDb.grades)) {
    structure[gradeId] = { name: grade.name, subjects: {} };
    for (const [subId, sub] of Object.entries(grade.subjects)) {
      structure[gradeId].subjects[subId] = { name: sub.name, icon: sub.icon || 'book', topics: {} };
      for (const [topId, top] of Object.entries(sub.topics)) {
        structure[gradeId].subjects[subId].topics[topId] = { name: top.name, tests: {} };
        for (const [testId, test] of Object.entries(top.tests)) {
          structure[gradeId].subjects[subId].topics[topId].tests[testId] = {
            name: test.name,
            questionCount: test.questions ? test.questions.length : 0
          };
        }
      }
    }
  }
  return structure;
}

// Helper to get questions by specific path
function getQuestionsFromPath(gradeId, subId, topId, testId) {
  try {
    return questionDb.grades[gradeId].subjects[subId].topics[topId].tests[testId].questions;
  } catch(e) {
    return null;
  }
}

// IN-MEMORY GAME ROOM STORAGE
// pin -> RoomObject
const rooms = new Map();

// Helper to generate unique 6-digit PIN
function generateUniquePin() {
  for (let attempt = 0; attempt < 1000; attempt++) {
    const pin = Math.floor(100000 + Math.random() * 900000).toString();
    if (!rooms.has(pin)) return pin;
  }
  return null;
}

// 6. REST API ENDPOINTS

// Categories List Endpoint
app.get('/api/categories', (req, res) => {
  res.json({
    success: true,
    categories: getStructureList()
  });
});

// Create Room Endpoint (Host calls this)
app.post('/api/rooms', roomCreateLimiter, (req, res) => {
  const clientIp = getClientIp(req);
  const banStatus = isIpBanned(clientIp);
  if (banStatus.banned) {
    return res.status(429).json({
      success: false,
      error: `IP adresiniz engellendi. Kalan süre: ${banStatus.remainingSec} saniye.`
    });
  }

  const pin = generateUniquePin();
  if (!pin) {
    return res.status(500).json({ success: false, error: 'Oda PIN oluşturulamadı. Sunucu dolu.' });
  }

  // Varsayılan olarak 9. Sınıf Tarih - İlk Çağ - Kolay testi seçili gelsin
  const defaultPath = { gradeId: '9', subId: 'tarih', topId: 'ilkcag', testId: 'kolay' };
  const defaultQuestions = getQuestionsFromPath('9', 'tarih', 'ilkcag', 'kolay') || [];

  // Room state stored strictly in RAM (zero overhead, references shared questions array)
  const room = {
    pin,
    hostSocketId: null,
    hostIp: clientIp,
    state: 'LOBBY', // 'LOBBY', 'QUESTION', 'RESULT', 'LEADERBOARD', 'PODIUM'
    selectedPath: defaultPath,
    questions: defaultQuestions,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    currentQuestionIndex: -1,
    questionStartTime: 0,
    questionDuration: 20, // 20 seconds per question
    timerInterval: null,
    remainingSeconds: 20,
    players: new Map(), // socketId -> { id, nickname, score, currentAnswer, answeredAt, ip, lastEarnedPoints }
    createdAt: Date.now()
  };

  rooms.set(pin, room);
  console.log(`[ROOM CREATED] PIN: ${pin} by IP: ${clientIp}`);

  res.json({ success: true, pin, selectedPath: defaultPath });
});

// Verify Room PIN Endpoint (Player pre-checks PIN)
app.post('/api/check-pin', pinVerifyLimiter, (req, res) => {
  const clientIp = getClientIp(req);
  const banStatus = isIpBanned(clientIp);
  if (banStatus.banned) {
    return res.status(429).json({
      success: false,
      banned: true,
      error: `Güvenlik Protokolü: 10 hatalı deneme nedeniyle IP engellendi. Kalan: ${banStatus.remainingSec} sn.`
    });
  }

  const pin = sanitizeString(req.body.pin, 6);
  if (!/^\d{6}$/.test(pin)) {
    recordFailedPinAttempt(clientIp);
    return res.status(400).json({ success: false, error: 'Geçersiz 6 haneli PIN.' });
  }

  const room = rooms.get(pin);
  if (!room) {
    recordFailedPinAttempt(clientIp);
    return res.status(404).json({ success: false, error: 'Oda bulunamadı. Lütfen PIN kodunu kontrol edin.' });
  }

  if (room.state !== 'LOBBY') {
    return res.status(403).json({ success: false, error: 'Oyun zaten başlamış veya kapalı.' });
  }

  // Reset failed attempts on success
  resetFailedPinAttempts(clientIp);
  res.json({ success: true, state: room.state });
});

// 7. SOCKET.IO REAL-TIME ZERO-TRUST LOGIC & FLOOD DEBOUNCING
// Per-socket throttle tracker: socketId -> lastTimestamp
const socketThrottleMap = new Map();

function isThrottled(key, intervalMs = 1000) {
  const now = Date.now();
  const lastTime = socketThrottleMap.get(key) || 0;
  if (now - lastTime < intervalMs) {
    return true; // Flooding, throttled
  }
  socketThrottleMap.set(key, now);
  return false;
}

// Room Leaderboard Calculator
function getLeaderboard(room, limit = 10) {
  const playersList = Array.from(room.players.values()).map(p => ({
    nickname: p.nickname,
    score: p.score
  }));
  playersList.sort((a, b) => b.score - a.score);
  return playersList.slice(0, limit);
}

// Question Distribution Calculator (Only counts A, B, C, D)
function getDistribution(room) {
  const counts = { A: 0, B: 0, C: 0, D: 0 };
  for (const player of room.players.values()) {
    if (player.currentAnswer && counts[player.currentAnswer] !== undefined) {
      counts[player.currentAnswer]++;
    }
  }
  return counts;
}

// End current question and show result to Host and Players
function finishQuestion(room) {
  if (!room || room.state !== 'QUESTION') return;

  if (room.timerInterval) {
    clearInterval(room.timerInterval);
    room.timerInterval = null;
  }

  room.state = 'RESULT';
  const roomQuestions = room.questions || [];
  const qObj = roomQuestions[room.currentQuestionIndex];
  const maxDurationMs = room.questionDuration * 1000;

  // Calculate scores ONLY when the timer reaches zero!
  for (const player of room.players.values()) {
    if (player.currentAnswer) {
      const isCorrect = (player.currentAnswer === qObj.correct);
      if (isCorrect) {
        const respTime = player.responseTimeMs !== undefined ? player.responseTimeMs : maxDurationMs;
        const speedRatio = Math.max(0, 1 - (respTime / maxDurationMs));
        const earned = Math.round(500 + 500 * speedRatio);
        player.score += earned;
        player.lastEarnedPoints = earned;
      } else {
        player.lastEarnedPoints = 0;
      }
    } else {
      player.lastEarnedPoints = 0;
    }
  }

  const distribution = getDistribution(room);
  let totalAnswered = 0;
  for (const p of room.players.values()) {
    if (p.currentAnswer) totalAnswered++;
  }

  // Sort players to calculate ranks
  const sortedPlayers = Array.from(room.players.values()).sort((a, b) => b.score - a.score);
  const playerRankMap = new Map();
  sortedPlayers.forEach((p, idx) => {
    playerRankMap.set(p.id, idx + 1);
  });

  // 1. Send detailed question outcome to HOST ONLY
  if (room.hostSocketId) {
    io.to(room.hostSocketId).emit('host_question_result', {
      correct: qObj.correct,
      distribution,
      totalAnswered,
      totalPlayers: room.players.size,
      leaderboard: getLeaderboard(room, 5)
    });
  }

  // 2. ZERO-TRUST: Send only player-specific result to MOBILE PLAYERS
  // NO question text, NO option text, NO other options payload!
  for (const player of room.players.values()) {
    const isCorrect = (player.currentAnswer === qObj.correct);
    io.to(player.id).emit('player_question_result', {
      action: 'show_result',
      isCorrect,
      selectedAnswer: player.currentAnswer || null,
      earnedPoints: player.lastEarnedPoints,
      totalScore: player.score,
      rank: playerRankMap.get(player.id) || 1,
      totalPlayers: room.players.size
    });
  }
}

io.on('connection', (socket) => {
  const clientIp = getSocketIp(socket);

  // Check ban before processing any events
  const banStatus = isIpBanned(clientIp);
  if (banStatus.banned) {
    socket.emit('auth_error', {
      message: `IP engellendi. Kalan süre: ${banStatus.remainingSec} saniye.`
    });
    socket.disconnect(true);
    return;
  }

  // --- HOST REGISTRATION ---
  socket.on('host_join_room', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const room = rooms.get(pin);

    if (!room) {
      socket.emit('auth_error', { message: 'Geçersiz oda PIN.' });
      return;
    }

    // Set Host Socket ID
    room.hostSocketId = socket.id;
    socket.join(pin);
    console.log(`[HOST ATTACHED] Room PIN: ${pin}, Host Socket: ${socket.id}`);

    const pathData = room.selectedPath;
    let catName = '';
    try { catName = questionDb.grades[pathData.gradeId].subjects[pathData.subId].topics[pathData.topId].tests[pathData.testId].name; } catch(e){}

    socket.emit('host_connected', {
      pin: room.pin,
      state: room.state,
      categories: getStructureList(),
      selectedPath: room.selectedPath,
      categoryName: catName,
      players: Array.from(room.players.values()).map(p => ({ id: p.id, nickname: p.nickname, score: p.score }))
    });
  });

  // --- PLAYER REGISTRATION ---
  socket.on('player_join_room', (data) => {
    // Debounce fast connection attempts
    if (isThrottled(socket.id + '_join', 500)) return;

    const currentBan = isIpBanned(clientIp);
    if (currentBan.banned) {
      socket.emit('auth_error', { message: `IP engellendi. Kalan: ${currentBan.remainingSec} sn.` });
      return;
    }

    const pin = sanitizeString(data?.pin, 6);
    const rawNickname = data?.nickname;

    if (!/^\d{6}$/.test(pin)) {
      recordFailedPinAttempt(clientIp);
      socket.emit('auth_error', { message: 'PIN 6 haneli rakamlardan oluşmalıdır.' });
      return;
    }

    const room = rooms.get(pin);
    if (!room) {
      recordFailedPinAttempt(clientIp);
      socket.emit('auth_error', { message: 'Oda bulunamadı. Lütfen PIN kontrol ediniz.' });
      return;
    }

    if (room.state !== 'LOBBY') {
      socket.emit('auth_error', { message: 'Oyun zaten başlamış veya kapalı.' });
      return;
    }

    const nickname = sanitizeNickname(rawNickname);
    if (!nickname || nickname.length < 2) {
      socket.emit('auth_error', { message: 'Geçersiz takma ad (En az 2 karakter, özel karakter içermez).' });
      return;
    }

    // Check duplicate nickname in room
    const isNameTaken = Array.from(room.players.values()).some(
      p => p.nickname.toLowerCase() === nickname.toLowerCase()
    );
    if (isNameTaken) {
      socket.emit('auth_error', { message: 'Bu takma ad odada zaten kullanılıyor.' });
      return;
    }

    // Success: Clear failed attempts for this IP
    resetFailedPinAttempts(clientIp);

    // Save player in RAM
    const playerObj = {
      id: socket.id,
      nickname,
      score: 0,
      currentAnswer: null,
      answeredAt: 0,
      ip: clientIp,
      lastEarnedPoints: 0
    };

    room.players.set(socket.id, playerObj);
    socket.join(pin);

    console.log(`[PLAYER JOINED] PIN: ${pin}, Nick: ${nickname}, Socket: ${socket.id}, IP: ${clientIp}`);

    // Confirm to player
    socket.emit('player_joined', {
      pin: room.pin,
      nickname,
      state: room.state
    });

    // Notify Host of updated player list
    if (room.hostSocketId) {
      io.to(room.hostSocketId).emit('player_list_updated', {
        count: room.players.size,
        players: Array.from(room.players.values()).map(p => ({ id: p.id, nickname: p.nickname, score: p.score }))
      });
    }
  });

  // --- ACCESS CONTROL: HOST-ONLY GAME FLOW COMMANDS ---
  function validateHost(pin) {
    const room = rooms.get(pin);
    if (!room) return null;
    if (room.hostSocketId !== socket.id) {
      socket.emit('error_msg', 'Erişim reddedildi: Bu işlemi yalnızca Host gerçekleştirebilir.');
      return null;
    }
    return room;
  }

  // Host kicks a player
  socket.on('host_kick_player', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const playerId = sanitizeString(data?.playerId, 100);
    const room = validateHost(pin);
    if (!room) return;

    if (room.players.has(playerId)) {
      const p = room.players.get(playerId);
      console.log(`[HOST KICKED] Player ${p.nickname} from Room ${pin}`);
      room.players.delete(playerId);
      
      // Notify the kicked player
      io.to(playerId).emit('room_closed', { message: 'Host tarafından odadan çıkarıldınız.' });
      
      // Update Host UI
      io.to(room.hostSocketId).emit('player_list_updated', {
        count: room.players.size,
        players: Array.from(room.players.values()).map(pl => ({ id: pl.id, nickname: pl.nickname, score: pl.score }))
      });
    }
  });

  // Host selects question path in lobby
  socket.on('host_select_category', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const pathData = data?.selectedPath;
    const room = validateHost(pin);
    if (!room) return;

    if (room.state !== 'LOBBY') {
      socket.emit('error_msg', 'Kategori yalnızca lobi aşamasında değiştirilebilir.');
      return;
    }

    if (!pathData || !pathData.gradeId || !pathData.subId || !pathData.topId || !pathData.testId) {
       socket.emit('error_msg', 'Geçersiz kategori yolu.');
       return;
    }

    const qs = getQuestionsFromPath(pathData.gradeId, pathData.subId, pathData.topId, pathData.testId);
    if (!qs || qs.length === 0) {
      socket.emit('error_msg', 'Seçilen test bulunamadı veya boş.');
      return;
    }

    let catName = '';
    try { catName = questionDb.grades[pathData.gradeId].subjects[pathData.subId].topics[pathData.topId].tests[pathData.testId].name; } catch(e){}

    room.selectedPath = pathData;
    room.questions = qs;
    room.settings = {
      questionDuration: parseInt(data.settings?.questionDuration) || 20,
      autoFinish: data.settings?.autoFinish !== false,
      autoSkipLeaderboard: data.settings?.autoSkipLeaderboard === true
    };
    console.log(`[TEST SELECTED] Room PIN: ${pin}, Test: ${catName}`);

    socket.emit('host_category_updated', {
      selectedPath: pathData,
      categoryName: catName,
      questionCount: room.questions.length
    });
  });

  // Host starts game or moves to next question
  socket.on('host_next_question', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const room = validateHost(pin);
    if (!room) return;
    if (room) room.lastActivity = Date.now();

    // Throttle host clicks
    if (isThrottled(socket.id + '_next', 800)) return;

    if (room.timerInterval) {
      clearInterval(room.timerInterval);
      room.timerInterval = null;
    }
    
    if (room.leaderboardTimeout) {
      clearTimeout(room.leaderboardTimeout);
      room.leaderboardTimeout = null;
    }

    const roomQuestions = room.questions || [];

    room.currentQuestionIndex += 1;

    // Check if game finished
    if (room.currentQuestionIndex >= roomQuestions.length) {
      room.state = 'PODIUM';
      const finalLeaderboard = getLeaderboard(room, 10);
      
      io.to(room.hostSocketId).emit('host_game_over', {
        podium: finalLeaderboard.slice(0, 3),
        leaderboard: finalLeaderboard
      });

      // Notify mobile players of game over
      const sorted = Array.from(room.players.values()).sort((a, b) => b.score - a.score);
      sorted.forEach((p, idx) => {
        io.to(p.id).emit('player_game_over', {
          rank: idx + 1,
          totalScore: p.score,
          totalPlayers: room.players.size
        });
      });
      return;
    }

    // Prepare Question
    const qIndex = room.currentQuestionIndex;
    const qObj = roomQuestions[qIndex];
    room.state = 'QUESTION';
    room.questionStartTime = Date.now();
    room.questionDuration = room.settings?.questionDuration || 20;
    room.remainingSeconds = room.questionDuration;

    // Reset player answers for this question
    for (const player of room.players.values()) {
      player.currentAnswer = null;
      player.answeredAt = 0;
      player.responseTimeMs = 0;
      player.lastEarnedPoints = 0;
    }

    // 1. Send FULL QUESTION AND OPTIONS to HOST SMARTBOARD
    // Notice: We NEVER send `correct` answer even to Host client in network payload during countdown!
    
    let catName = '';
    try { catName = questionDb.grades[room.selectedPath.gradeId].subjects[room.selectedPath.subId].topics[room.selectedPath.topId].tests[room.selectedPath.testId].name; } catch(e){}

    io.to(room.hostSocketId).emit('host_show_question', {
      questionIndex: qIndex,
      totalQuestions: roomQuestions.length,
      categoryName: catName,
      categoryId: room.selectedCategory,
      q: qObj.q,
      options: qObj.options,
      duration: room.questionDuration,
      totalPlayers: room.players.size,
      answeredCount: 0
    });

    // 2. CRITICAL ZERO-TRUST: Send strictly "show_buttons" to MOBILE PLAYERS
    // ZERO question text, ZERO option texts, ZERO answers!
    for (const player of room.players.values()) {
      io.to(player.id).emit('player_show_buttons', {
        action: 'show_buttons',
        questionIndex: qIndex + 1,
        totalQuestions: roomQuestions.length,
        duration: room.questionDuration
      });
    }

    // Start 1-second server countdown
    room.timerInterval = setInterval(() => {
      room.remainingSeconds -= 1;

      // Broadcast tick to host AND players
      io.to(pin).emit('timer_tick', {
        remainingSeconds: room.remainingSeconds
      });

      if (room.remainingSeconds <= 0) {
        finishQuestion(room);
      }
    }, 1000);
  });

  // Host shows leaderboard between questions
  socket.on('host_show_leaderboard', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const room = validateHost(pin);
    if (!room) return;

    const roomQuestions = room.questions || [];

    room.state = 'LEADERBOARD';
    const topPlayers = getLeaderboard(room, 5);

    let catName = '';
    try { catName = questionDb.grades[room.selectedPath.gradeId].subjects[room.selectedPath.subId].topics[room.selectedPath.topId].tests[room.selectedPath.testId].name; } catch(e){}

    io.to(room.hostSocketId).emit('host_leaderboard_view', {
      leaderboard: topPlayers,
      questionIndex: room.currentQuestionIndex + 1,
      totalQuestions: roomQuestions.length,
      categoryName: catName
    });

    // Notify players of current leaderboard view
    const sorted = Array.from(room.players.values()).sort((a, b) => b.score - a.score);
    sorted.forEach((p, idx) => {
      io.to(p.id).emit('player_leaderboard_view', {
        rank: idx + 1,
        score: p.score,
        totalPlayers: room.players.size
      });
    });

    // Auto-skip leaderboard if enabled
    if (room.settings?.autoSkipLeaderboard) {
      if (room.leaderboardTimeout) clearTimeout(room.leaderboardTimeout);
      room.leaderboardTimeout = setTimeout(() => {
        // If still in LEADERBOARD state after 10s
        if (room.state === 'LEADERBOARD') {
          if (room.currentQuestionIndex + 1 >= room.questions.length) {
            // End game if it was the last question
            room.state = 'PODIUM';
            const finalLeaderboard = getLeaderboard(room, 10);
            io.to(room.hostSocketId).emit('host_game_over', {
              podium: finalLeaderboard.slice(0, 3),
              leaderboard: finalLeaderboard
            });
            sorted.forEach((p, idx) => {
              io.to(p.id).emit('player_game_over', { rank: idx + 1, totalScore: p.score, totalPlayers: room.players.size });
            });
          } else {
            // Tell host to go to next question
            io.to(room.hostSocketId).emit('auto_next_question');
          }
        }
      }, 10000); // 10 seconds
    }
  });

  // Host ends game early or triggers podium
  socket.on('host_end_game', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const room = validateHost(pin);
    if (!room) return;

    if (room.timerInterval) {
      clearInterval(room.timerInterval);
      room.timerInterval = null;
    }

    room.state = 'PODIUM';
    const finalLeaderboard = getLeaderboard(room, 10);

    io.to(room.hostSocketId).emit('host_game_over', {
      podium: finalLeaderboard.slice(0, 3),
      leaderboard: finalLeaderboard
    });

    const sorted = Array.from(room.players.values()).sort((a, b) => b.score - a.score);
    sorted.forEach((p, idx) => {
      io.to(p.id).emit('player_game_over', {
        rank: idx + 1,
        totalScore: p.score,
        totalPlayers: room.players.size
      });
    });
  });

  // --- PLAYER SUBMITS ANSWER ---
  socket.on('player_submit_answer', (data) => {
    // 5. DEBOUNCE / THROTTLE: Prevent rapid flood attacks (1 sec throttle per socket)
    if (isThrottled(socket.id + '_answer', 500)) {
      return;
    }

    const pin = sanitizeString(data?.pin, 6);
    const answer = sanitizeString(data?.answer, 1).toUpperCase();

    if (!['A', 'B', 'C', 'D'].includes(answer)) {
      return;
    }

    const room = rooms.get(pin);
    if (!room || room.state !== 'QUESTION') {
      return; // Answer rejected if question is not actively running
    }

    const player = room.players.get(socket.id);
    if (!player) return;

    // Check if player has already answered this question
    if (player.currentAnswer !== null) {
      return; // Multiple submissions per question strictly ignored
    }

    // Calculate response time and record on the backend
    const now = Date.now();
    const responseTimeMs = Math.max(0, now - room.questionStartTime);
    const maxDurationMs = room.questionDuration * 1000;

    if (responseTimeMs > maxDurationMs + 1000) {
      // Answer arrived after question expired
      return;
    }

    player.currentAnswer = answer;
    player.answeredAt = now;
    player.responseTimeMs = responseTimeMs;

    // Acknowledge submission to player (NO feedback yet whether right/wrong!)
    socket.emit('player_answer_received', {
      selectedAnswer: answer
    });

    // Count how many answered
    let answeredCount = 0;
    for (const p of room.players.values()) {
      if (p.currentAnswer !== null) answeredCount++;
    }

    // Notify Host of updated answer count
    if (room.hostSocketId) {
      io.to(room.hostSocketId).emit('host_answer_update', {
        answeredCount,
        totalPlayers: room.players.size
      });
    }

    // Auto-finish if everyone answered and setting is enabled
    if (room.settings?.autoFinish && answeredCount >= room.players.size) {
      if (room.timerInterval) {
        clearInterval(room.timerInterval);
        room.timerInterval = null;
      }
      room.remainingSeconds = 0;
      io.to(pin).emit('timer_tick', { remainingSeconds: 0 });
      finishQuestion(room);
    }
  });

  // --- DISCONNECT HANDLING ---
  socket.on('disconnect', () => {
    socketThrottleMap.delete(socket.id);

    // Check if socket was a host or player in any room
    for (const [pin, room] of rooms.entries()) {
      if (room.hostSocketId === socket.id) {
        console.log(`[HOST DISCONNECTED] Room PIN: ${pin}`);
        if (room.timerInterval) clearInterval(room.timerInterval);
        io.to(pin).emit('room_closed', { message: 'Host bağlantısı kesildi. Oyun sonlandırıldı.' });
        rooms.delete(pin);
        break;
      }

      if (room.players.has(socket.id)) {
        const p = room.players.get(socket.id);
        console.log(`[PLAYER DISCONNECTED] PIN: ${pin}, Nick: ${p.nickname}`);
        room.players.delete(socket.id);

        // Update Host
        if (room.hostSocketId) {
          io.to(room.hostSocketId).emit('player_list_updated', {
            count: room.players.size,
            players: Array.from(room.players.values()).map(pl => ({ id: pl.id, nickname: pl.nickname, score: pl.score }))
          });

          // If during question, update answer counter. Never finish question early.
          if (room.state === 'QUESTION') {
            let answered = 0;
            for (const pl of room.players.values()) {
              if (pl.currentAnswer !== null) answered++;
            }
            io.to(room.hostSocketId).emit('host_answer_update', {
              answeredCount: answered,
              totalPlayers: room.players.size
            });
          }
        }
        break;
      }
    }
  });
});

// --- ZOMBIE ROOM GARBAGE COLLECTOR (Memory Leak & Timeout Fix) ---
// Runs every 5 minutes. Clears rooms that have been inactive for more than 10 minutes.
setInterval(() => {
  const now = Date.now();
  let clearedCount = 0;
  for (const [pin, room] of rooms.entries()) {
    const inactiveMs = now - (room.lastActivity || room.createdAt);
    const isInactive10Mins = inactiveMs > 10 * 60 * 1000;
    
    if (isInactive10Mins) {
      if (room.timerInterval) clearInterval(room.timerInterval);
      
      // Notify clients before closing
      io.to(pin).emit('room_closed', { message: 'Oda uzun süre hareketsiz kaldığı için kapatıldı (10dk zaman aşımı).' });
      io.in(pin).socketsLeave(pin);
      
      rooms.delete(pin);
      clearedCount++;
    }
  }
  if (clearedCount > 0) {
    console.log(`[GARBAGE COLLECTOR] Cleared ${clearedCount} inactive rooms due to 10-minute timeout.`);
  }
}, 5 * 60 * 1000);

// START SERVER
server.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`PARS LAB RETRO QUIZ SERVER RUNNING ON PORT ${PORT}`);
  console.log(`Host Interface  : http://localhost:${PORT}/host.html`);
  console.log(`Player Interface: http://localhost:${PORT}/`);
  console.log(`===================================================`);
});
