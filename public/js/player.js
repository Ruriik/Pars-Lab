(function () {
  'use strict';

  const { $, setButton, showScreen, toast, setTimer, countUp, confetti, vibrate } = window.UI;
  const SCREENS = ['sJoin', 'sWait', 'sQuestion', 'sLocked', 'sResult', 'sOver', 'sClosed'];
  const SESSION_KEY = 'parslab_session';
  const SHAPES = { A: 'shape-a', B: 'shape-b', C: 'shape-c', D: 'shape-d' };

  const state = { socket: null, pin: '', nickname: '', token: '', duration: 20, answered: false, ended: false };
  const answers = Array.from(document.querySelectorAll('.answer'));
  const show = (id) => showScreen(SCREENS, id);

  function saveSession() {
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ pin: state.pin, token: state.token })); } catch (e) { /* private mode */ }
  }
  function loadSession() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null'); } catch (e) { return null; }
  }
  function clearSession() {
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ }
    state.token = '';
  }

  function banner(text) {
    const b = $('connBanner');
    if (!text) { b.hidden = true; return; }
    $('connBannerText').textContent = text;
    b.hidden = false;
  }

  /* ─── Join form ─── */
  const pinInput = $('pinInput');
  const nickInput = $('nickInput');
  const joinBtn = $('joinBtn');

  pinInput.addEventListener('input', () => {
    pinInput.value = pinInput.value.replace(/\D/g, '').slice(0, 6);
    $('pinField').classList.remove('has-error');
    if (pinInput.value.length === 6 && !nickInput.value) nickInput.focus();
  });
  nickInput.addEventListener('input', () => $('nickField').classList.remove('has-error'));

  function setJoinError(msg, field) {
    $('joinError').textContent = msg || '';
    ['pinField', 'nickField'].forEach((f) => $(f).classList.remove('has-error'));
    if (field) {
      void $(field).offsetWidth;
      $(field).classList.add('has-error');
    }
  }

  function resetJoinButton() {
    joinBtn.disabled = false;
    setButton(joinBtn, 'login', 'Yarışmaya Katıl');
  }

  $('joinForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pin = pinInput.value.trim();
    const nick = nickInput.value.trim();
    if (!/^\d{6}$/.test(pin)) return setJoinError('PIN 6 haneli bir sayı olmalı.', 'pinField');
    if (nick.length < 2) return setJoinError('Takma ad en az 2 karakter olmalı.', 'nickField');

    setJoinError('');
    joinBtn.disabled = true;
    setButton(joinBtn, 'loader', 'Bağlanıyor…', true);

    try {
      const res = await fetch('/api/check-pin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin })
      });
      const data = await res.json().catch(() => ({}));
      if (!data.success) {
        resetJoinButton();
        return setJoinError(data.error || 'Oda doğrulanamadı.', 'pinField');
      }
    } catch (err) {
      resetJoinButton();
      return setJoinError('Sunucuya ulaşılamadı. İnternet bağlantını kontrol et.');
    }

    state.pin = pin;
    state.nickname = nick;
    clearSession();
    connect();
  });

  /* ─── Socket ─── */
  function connect() {
    if (state.socket) state.socket.disconnect();
    const socket = io({ transports: ['websocket', 'polling'], reconnectionAttempts: 12, reconnectionDelayMax: 4000 });
    state.socket = socket;

    socket.on('connect', () => {
      banner('');
      if (state.token) socket.emit('player_rejoin', { pin: state.pin, sessionToken: state.token });
      else socket.emit('player_join_room', { pin: state.pin, nickname: state.nickname });
    });

    socket.on('connect_error', (err) => {
      if (err && err.message && /engellendi|fazla/i.test(err.message)) {
        socket.disconnect();
        resetJoinButton();
        setJoinError(err.message);
        show('sJoin');
        return;
      }
      if (state.token) banner('Bağlantı yeniden kuruluyor…');
    });

    socket.on('disconnect', (reason) => {
      if (state.ended) return;
      if (reason === 'io server disconnect' || reason === 'io client disconnect') return;
      banner('Bağlantı yeniden kuruluyor…');
    });

    socket.io.on('reconnect_failed', () => {
      banner('');
      closed('Bağlantı kurulamadı', 'Sunucuya yeniden bağlanılamadı. Sayfayı yenileyip tekrar dene.');
    });

    socket.on('auth_error', (d) => {
      clearSession();
      socket.disconnect();
      resetJoinButton();
      show('sJoin');
      setJoinError(d && d.message ? d.message : 'Katılım reddedildi.');
    });

    socket.on('rejoin_failed', () => {
      clearSession();
      socket.disconnect();
      banner('');
      resetJoinButton();
      show('sJoin');
      setJoinError('Önceki oturumun sona erdi. Tekrar katıl.');
    });

    socket.on('player_joined', (d) => {
      state.pin = d.pin;
      state.nickname = d.nickname;
      state.token = d.sessionToken;
      saveSession();
      resetJoinButton();
      $('waitNick').textContent = d.nickname;
      $('waitPin').textContent = 'PIN ' + d.pin;
      if (typeof d.totalScore === 'number') $('resTotal').dataset.value = d.totalScore;
      if (!d.resumed || d.state === 'LOBBY') show('sWait');
      if (!d.resumed) vibrate(30);
      else toast('Oturumun geri yüklendi', 'ok');
    });

    socket.on('host_status', (d) => {
      const online = !!(d && d.online);
      $('hostDot').classList.toggle('off', !online);
      $('hostStatusText').textContent = online ? 'Eğitmen çevrim içi' : 'Eğitmen bekleniyor';
      banner(online ? '' : 'Eğitmen bağlantısı bekleniyor…');
    });

    socket.on('player_show_buttons', (d) => {
      state.answered = false;
      state.duration = d.duration;
      $('qLabel').textContent = `Soru ${d.questionIndex} / ${d.totalQuestions}`;
      setTimer($('pTimer'), d.duration, d.duration);
      answers.forEach((b) => {
        b.disabled = false;
        b.classList.remove('dim', 'chosen');
        b.style.animation = 'none';
        void b.offsetWidth;
        b.style.animation = '';
      });
      show('sQuestion');
      vibrate([20, 40, 20]);
    });

    socket.on('timer_tick', (d) => {
      setTimer($('pTimer'), d.remainingSeconds, state.duration);
      if (d.remainingSeconds > 0 && d.remainingSeconds <= 3 && !state.answered) vibrate(15);
    });

    socket.on('player_answer_received', (d) => {
      state.answered = true;
      const letter = d.selectedAnswer;
      const gem = $('lockedGem');
      gem.className = 'locked-gem gem-' + letter.toLowerCase();
      gem.replaceChildren(window.UI.icon(SHAPES[letter], 'icon-xl'), window.UI.el('span', { text: letter }));
      setTimeout(() => show('sLocked'), 260);
    });

    socket.on('player_question_result', (d) => {
      const section = $('sResult');
      section.classList.toggle('is-correct', d.isCorrect);
      section.classList.toggle('is-wrong', !d.isCorrect);
      const badge = $('resBadge');
      badge.className = 'result-badge' + (d.isCorrect ? '' : ' bad');
      badge.replaceChildren(window.UI.icon(d.isCorrect ? 'check' : d.selectedAnswer ? 'x' : 'clock', 'icon-xl'));
      $('resTitle').textContent = d.isCorrect ? 'Doğru!' : d.selectedAnswer ? 'Yanlış' : 'Süre doldu';
      $('resPoints').textContent = d.isCorrect ? `+${d.earnedPoints}` : '+0';
      $('resStreak').hidden = !(d.isCorrect && d.streak >= 2);
      $('resStreakText').textContent = `${d.streak} doğru seri`;
      $('resRank').textContent = `#${d.rank}`;
      show('sResult');
      countUp($('resTotal'), d.totalScore);
      if (d.isCorrect) {
        vibrate([30, 50, 60]);
        if (d.rank === 1) confetti({ count: 90, duration: 2600 });
      } else {
        vibrate(120);
      }
    });

    socket.on('player_leaderboard_view', (d) => {
      $('resRank').textContent = `#${d.rank}`;
      countUp($('resTotal'), d.score);
    });

    socket.on('player_game_over', (d) => {
      state.ended = true;
      clearSession();
      $('overRank').textContent = `#${d.rank}`;
      $('overScore').textContent = Number(d.totalScore).toLocaleString('tr-TR');
      $('overOf').textContent = d.totalPlayers;
      $('overTitle').textContent = d.rank === 1 ? 'Şampiyonsun!' : d.rank <= 3 ? 'Kürsüdesin!' : 'Final sıran';
      const medal = $('overMedal');
      medal.className = 'medal' + (d.rank === 2 ? ' silver' : d.rank === 3 ? ' bronze' : d.rank > 3 ? ' plain' : '');
      medal.replaceChildren(window.UI.icon(d.rank === 1 ? 'crown' : 'trophy', 'icon-xl'));
      show('sOver');
      if (d.rank <= 3) confetti();
    });

    socket.on('room_closed', (d) => {
      state.ended = true;
      clearSession();
      banner('');
      closed(d && d.kicked ? 'Odadan çıkarıldın' : 'Oda kapandı', (d && d.message) || 'Oda kapatıldı.');
    });
  }

  function closed(title, msg) {
    $('closedTitle').textContent = title;
    $('closedMsg').textContent = msg;
    show('sClosed');
  }

  /* ─── Answers ─── */
  answers.forEach((btn) => {
    btn.addEventListener('click', () => {
      if (state.answered || !state.socket) return;
      state.answered = true;
      answers.forEach((b) => {
        b.disabled = true;
        b.classList.toggle('chosen', b === btn);
        b.classList.toggle('dim', b !== btn);
      });
      vibrate(25);
      state.socket.emit('player_submit_answer', { pin: state.pin, answer: btn.dataset.answer });
    });
  });

  /* ─── Boot ─── */
  document.addEventListener('DOMContentLoaded', () => {
    const qrPin = new URLSearchParams(location.search).get('pin');
    const saved = loadSession();

    if (saved && /^\d{6}$/.test(saved.pin) && saved.token && (!qrPin || qrPin === saved.pin)) {
      state.pin = saved.pin;
      state.token = saved.token;
      banner('Oturum geri yükleniyor…');
      connect();
      return;
    }

    if (qrPin && /^\d{6}$/.test(qrPin)) {
      pinInput.value = qrPin;
      nickInput.focus();
      history.replaceState(null, '', '/');
    }
  });
})();
