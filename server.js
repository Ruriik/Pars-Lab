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

// Middleware for parsing JSON & serving static files
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 4. XSS PROTECTION & INPUT SANITIZATION
function sanitizeString(str, maxLen = 30) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/<[^>]*>?/gm, '') // Strip HTML tags
    .replace(/[&<>"'/]/g, (s) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
      '/': '&#x2F;'
    }[s] || ''))
    .trim()
    .slice(0, maxLen);
}

function sanitizeNickname(rawName) {
  if (typeof rawName !== 'string') return '';
  // Strip tags first
  let cleaned = rawName.replace(/<[^>]*>?/gm, '').trim();
  // Allow alphanumeric, space, underscore, dash, and Turkish letters
  cleaned = cleaned.replace(/[^a-zA-Z0-9_\-\sığüşöçİĞÜŞÖÇ]/g, '');
  return cleaned.trim().slice(0, 15);
}

// 5. HARDCODED 30 QUESTIONS IN BACKEND RAM
const QUESTIONS = [
  {
    q: "İstanbul'un fethinin gerçekleştiği yıl hangisidir?",
    options: { A: "1451", B: "1453", C: "1461", D: "1517" },
    correct: "B"
  },
  {
    q: "Hücrenin enerji santrali olarak bilinen organeli hangisidir?",
    options: { A: "Ribozom", B: "Lizozom", C: "Mitokondri", D: "Çekirdek" },
    correct: "C"
  },
  {
    q: "İstiklal Marşı'mızın şairi kimdir?",
    options: { A: "Namık Kemal", B: "Mehmet Akif Ersoy", C: "Ziya Gökalp", D: "Yahya Kemal" },
    correct: "B"
  },
  {
    q: "Türkiye'nin en yüksek dağı aşağıdakilerden hangisidir?",
    options: { A: "Erciyes", B: "Süphan", C: "Kaçkar", D: "Ağrı" },
    correct: "D"
  },
  {
    q: "Suyun kimyasal formülü nedir?",
    options: { A: "CO2", B: "H2O", C: "NaCl", D: "CH4" },
    correct: "B"
  },
  {
    q: "Türkiye Büyük Millet Meclisi hangi tarihte açılmıştır?",
    options: { A: "19 Mayıs 1919", B: "23 Nisan 1920", C: "29 Ekim 1923", D: "30 Ağustos 1922" },
    correct: "B"
  },
  {
    q: "Güneş sistemindeki en büyük gezegen hangisidir?",
    options: { A: "Mars", B: "Venüs", C: "Satürn", D: "Jüpiter" },
    correct: "D"
  },
  {
    q: "\"Suç ve Ceza\" adlı eserin yazarı kimdir?",
    options: { A: "Tolstoy", B: "Dostoyevski", C: "Puşkin", D: "Gogol" },
    correct: "B"
  },
  {
    q: "Dünyanın en uzun nehri hangisidir?",
    options: { A: "Amazon", B: "Nil", C: "Mississippi", D: "Tuna" },
    correct: "B"
  },
  {
    q: "İlk yerli romanımız \"Taaşşuk-ı Talat ve Fitnat\" kimin eseridir?",
    options: { A: "Şemsettin Sami", B: "Namık Kemal", C: "Ahmet Mithat", D: "Recaizade Mahmut" },
    correct: "A"
  },
  {
    q: "Fransız İhtilali hangi yılda başlamıştır?",
    options: { A: "1776", B: "1789", C: "1830", D: "1848" },
    correct: "B"
  },
  {
    q: "Işık hızı saniyede yaklaşık kaç kilometredir?",
    options: { A: "100.000", B: "200.000", C: "300.000", D: "400.000" },
    correct: "C"
  },
  {
    q: "Malazgirt Meydan Muharebesi hangi tarihte gerçekleşmiştir?",
    options: { A: "1048", B: "1071", C: "1176", D: "1299" },
    correct: "B"
  },
  {
    q: "Periyodik tablonun birinci elementi hangisidir?",
    options: { A: "Helyum", B: "Lityum", C: "Karbon", D: "Hidrojen" },
    correct: "D"
  },
  {
    q: "Türkiye'nin en büyük yüzölçümüne sahip gölü hangisidir?",
    options: { A: "Tuz Gölü", B: "Beyşehir Gölü", C: "Van Gölü", D: "Eğirdir Gölü" },
    correct: "C"
  },
  {
    q: "Birinci Dünya Savaşı hangi yıllar arasında gerçekleşmiştir?",
    options: { A: "1912-1913", B: "1914-1918", C: "1939-1945", D: "1919-1922" },
    correct: "B"
  },
  {
    q: "\"Hababam Sınıfı\" eserinin yazarı kimdir?",
    options: { A: "Aziz Nesin", B: "Rıfat Ilgaz", C: "Sabahattin Ali", D: "Orhan Veli" },
    correct: "B"
  },
  {
    q: "DNA'nın açılımı nedir?",
    options: { A: "Dinamik Nükleik Asit", B: "Deoksiribo Nükleik Asit", C: "Çift Sarmal Asit", D: "Deoksi Nitro Asit" },
    correct: "B"
  },
  {
    q: "Bir gün toplam kaç saniyedir?",
    options: { A: "3600", B: "14400", C: "86400", D: "124000" },
    correct: "C"
  },
  {
    q: "Osmanlı İmparatorluğu'nun kurucusu kimdir?",
    options: { A: "Orhan Gazi", B: "Osman Bey", C: "I. Murat", D: "Yıldırım Bayezid" },
    correct: "B"
  },
  {
    q: "Ekvator çizgisinin geçtiği kıtalardan biri aşağıdakilerden hangisidir?",
    options: { A: "Avrupa", B: "Antarktika", C: "Afrika", D: "Avustralya" },
    correct: "C"
  },
  {
    q: "Yerçekimi kanununu formüle eden bilim insanı kimdir?",
    options: { A: "Albert Einstein", B: "Isaac Newton", C: "Galileo Galilei", D: "Nikola Tesla" },
    correct: "B"
  },
  {
    q: "Olimpiyat bayrağında bulunan halka sayısı kaçtır?",
    options: { A: "3", B: "4", C: "5", D: "6" },
    correct: "C"
  },
  {
    q: "\"Nutuk\" adlı eser kime aittir?",
    options: { A: "İsmet İnönü", B: "Kazım Karabekir", C: "Fevzi Çakmak", D: "Mustafa Kemal Atatürk" },
    correct: "D"
  },
  {
    q: "Mona Lisa tablosu hangi ressama aittir?",
    options: { A: "Vincent van Gogh", B: "Pablo Picasso", C: "Leonardo da Vinci", D: "Michelangelo" },
    correct: "C"
  },
  {
    q: "Dünya Kupası ilk olarak hangi ülkede düzenlenmiştir?",
    options: { A: "Brezilya", B: "Uruguay", C: "İtalya", D: "Arjantin" },
    correct: "B"
  },
  {
    q: "İstiklal Marşı'nın bestecisi kimdir?",
    options: { A: "Osman Zeki Üngör", B: "Mehmet Akif Ersoy", C: "Cemal Reşit Rey", D: "Ahmet Adnan Saygun" },
    correct: "A"
  },
  {
    q: "Hangi coğrafi bölge Türkiye'nin en fazla ormanlık alanına sahiptir?",
    options: { A: "Akdeniz", B: "Ege", C: "Karadeniz", D: "Marmara" },
    correct: "C"
  },
  {
    q: "Cumhuriyet hangi tarihte ilan edilmiştir?",
    options: { A: "23 Nisan 1920", B: "29 Ekim 1923", C: "30 Ağustos 1922", D: "19 Mayıs 1919" },
    correct: "B"
  },
  {
    q: "Atomu parçalayan bilim insanı kimdir?",
    options: { A: "Marie Curie", B: "Albert Einstein", C: "Ernest Rutherford", D: "Niels Bohr" },
    correct: "C"
  }
];

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

  // Room state stored strictly in RAM
  const room = {
    pin,
    hostSocketId: null,
    hostIp: clientIp,
    state: 'LOBBY', // 'LOBBY', 'QUESTION', 'RESULT', 'LEADERBOARD', 'PODIUM'
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

  res.json({ success: true, pin });
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
  const qObj = QUESTIONS[room.currentQuestionIndex];
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

    socket.emit('host_connected', {
      pin: room.pin,
      state: room.state,
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

  // Host starts game or moves to next question
  socket.on('host_next_question', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const room = validateHost(pin);
    if (!room) return;

    // Throttle host clicks
    if (isThrottled(socket.id + '_next', 800)) return;

    if (room.timerInterval) {
      clearInterval(room.timerInterval);
      room.timerInterval = null;
    }

    room.currentQuestionIndex += 1;

    // Check if game finished
    if (room.currentQuestionIndex >= QUESTIONS.length) {
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
    const qObj = QUESTIONS[qIndex];
    room.state = 'QUESTION';
    room.questionStartTime = Date.now();
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
    io.to(room.hostSocketId).emit('host_show_question', {
      questionIndex: qIndex,
      totalQuestions: QUESTIONS.length,
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
        totalQuestions: QUESTIONS.length,
        duration: room.questionDuration
      });
    }

    // Start 1-second server countdown
    room.timerInterval = setInterval(() => {
      room.remainingSeconds -= 1;

      // Broadcast tick to host
      if (room.hostSocketId) {
        io.to(room.hostSocketId).emit('timer_tick', {
          remainingSeconds: room.remainingSeconds
        });
      }

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

    room.state = 'LEADERBOARD';
    const topPlayers = getLeaderboard(room, 5);

    io.to(room.hostSocketId).emit('host_leaderboard_view', {
      leaderboard: topPlayers,
      questionIndex: room.currentQuestionIndex + 1,
      totalQuestions: QUESTIONS.length
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

    // Notify Host of updated answer count ONLY.
    // The question NEVER finishes early, even if all players answered.
    // Strictly wait for the countdown timer to reach zero.
    if (room.hostSocketId) {
      io.to(room.hostSocketId).emit('host_answer_update', {
        answeredCount,
        totalPlayers: room.players.size
      });
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

// START SERVER
server.listen(PORT, () => {
  console.log(`===================================================`);
  console.log(`PARS LAB RETRO QUIZ SERVER RUNNING ON PORT ${PORT}`);
  console.log(`Host Interface  : http://localhost:${PORT}/host.html`);
  console.log(`Player Interface: http://localhost:${PORT}/`);
  console.log(`===================================================`);
});
