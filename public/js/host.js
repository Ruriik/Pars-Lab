(function () {
  'use strict';

  const { $, el, icon, setButton, showScreen, toast, setTimer, countUp, renderQr, confetti } = window.UI;
  const SCREENS = ['hLobby', 'hQuestion', 'hBoard', 'hPodium'];
  const SESSION_KEY = 'parslab_host';
  const LETTERS = ['A', 'B', 'C', 'D'];
  const AVATAR_COLORS = ['#5ce1e6', '#e8c37a', '#f0506e', '#4c8dff', '#3ddc97', '#c79bff', '#f5b83d'];

  const state = {
    socket: null, pin: '', token: '', db: {}, players: [],
    sel: { gradeId: '', subId: '', topId: '', testId: '' },
    duration: 20, qDuration: 20, isLast: false, kickId: null, lastFocus: null
  };
  const show = (id) => showScreen(SCREENS, id);
  const emit = (event, payload) => state.socket && state.socket.emit(event, Object.assign({ pin: state.pin }, payload));

  const avatarColor = (name) => {
    let h = 0;
    for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return AVATAR_COLORS[h % AVATAR_COLORS.length];
  };
  const initials = (name) => name.trim().slice(0, 2).toLocaleUpperCase('tr');

  function saveSession() {
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ pin: state.pin, token: state.token })); } catch (e) { /* ignore */ }
  }
  function loadSession() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null'); } catch (e) { return null; }
  }
  function clearSession() {
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ }
  }

  function setConn(online, text) {
    $('connDot').classList.toggle('off', !online);
    $('connText').textContent = text;
  }

  /* ─── PIN / QR ─── */
  function renderPin(target, pin) {
    const node = $(target);
    node.replaceChildren(...pin.split('').map((d) => el('span', { text: d })));
  }

  function setupPin() {
    const joinUrl = `${location.origin}/?pin=${encodeURIComponent(state.pin)}`;
    $('pinTop').textContent = `${state.pin.slice(0, 3)} ${state.pin.slice(3)}`;
    $('joinHost').textContent = location.host;
    $('qrUrl').textContent = joinUrl.replace(/^https?:\/\//, '');
    renderPin('pinDigits', state.pin);
    renderPin('pinDigitsLg', state.pin);
    renderQr($('qrSmall'), joinUrl);
    renderQr($('qrLarge'), joinUrl);
    $('pinPill').disabled = false;
    $('qrOpenTop').disabled = false;
  }

  function openDialog(id) {
    state.lastFocus = document.activeElement;
    $(id).hidden = false;
    const focusTarget = $(id).querySelector('button');
    if (focusTarget) focusTarget.focus();
  }
  function closeDialog(id) {
    $(id).hidden = true;
    if (state.lastFocus && state.lastFocus.focus) state.lastFocus.focus();
  }

  $('qrOpenTop').addEventListener('click', () => openDialog('qrDialog'));
  $('qrOpenCard').addEventListener('click', () => openDialog('qrDialog'));
  $('qrClose').addEventListener('click', () => closeDialog('qrDialog'));
  ['qrDialog', 'kickDialog'].forEach((id) => {
    $(id).addEventListener('click', (e) => { if (e.target === $(id)) closeDialog(id); });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!$('qrDialog').hidden) closeDialog('qrDialog');
    if (!$('kickDialog').hidden) closeDialog('kickDialog');
  });

  $('pinPill').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(state.pin);
      toast('PIN kopyalandı', 'ok');
    } catch (e) {
      toast('Kopyalanamadı', 'error');
    }
  });

  /* ─── Question bank ─── */
  const selects = { grade: $('gradeSel'), sub: $('subSel'), top: $('topSel'), test: $('testSel') };

  function fill(select, placeholder, map) {
    const opts = [el('option', { value: '', text: placeholder })];
    Object.entries(map || {}).forEach(([k, v]) => {
      opts.push(el('option', { value: k, text: v.name + (v.questionCount ? ` · ${v.questionCount} soru` : '') }));
    });
    select.replaceChildren(...opts);
    select.disabled = false;
  }
  function lock(select, placeholder) {
    select.replaceChildren(el('option', { value: '', text: placeholder }));
    select.disabled = true;
  }
  const node = (...keys) => keys.reduce((acc, [k, child]) => (acc && acc[k] ? (child ? acc[k][child] : acc[k]) : null), state.db);

  function updateApply() { $('applyBtn').disabled = !state.sel.testId; }

  function initBank(selectedPath) {
    fill(selects.grade, 'Sınıf seçin', state.db);
    const p = selectedPath || {};
    if (p.gradeId && state.db[p.gradeId]) {
      selects.grade.value = p.gradeId;
      onGrade();
      if (p.subId) { selects.sub.value = p.subId; onSub(); }
      if (p.topId) { selects.top.value = p.topId; onTop(); }
      if (p.testId) { selects.test.value = p.testId; state.sel.testId = p.testId; }
    }
    updateApply();
  }

  function onGrade() {
    state.sel = { gradeId: selects.grade.value, subId: '', topId: '', testId: '' };
    lock(selects.top, 'Önce ders seçin');
    lock(selects.test, 'Önce konu seçin');
    if (!state.sel.gradeId) lock(selects.sub, 'Önce sınıf seçin');
    else fill(selects.sub, 'Ders seçin', node([state.sel.gradeId, 'subjects']));
    updateApply();
  }
  function onSub() {
    Object.assign(state.sel, { subId: selects.sub.value, topId: '', testId: '' });
    lock(selects.test, 'Önce konu seçin');
    if (!state.sel.subId) lock(selects.top, 'Önce ders seçin');
    else fill(selects.top, 'Konu seçin', node([state.sel.gradeId, 'subjects'], [state.sel.subId, 'topics']));
    updateApply();
  }
  function onTop() {
    Object.assign(state.sel, { topId: selects.top.value, testId: '' });
    if (!state.sel.topId) lock(selects.test, 'Önce konu seçin');
    else fill(selects.test, 'Test seçin', node([state.sel.gradeId, 'subjects'], [state.sel.subId, 'topics'], [state.sel.topId, 'tests']));
    updateApply();
  }
  selects.grade.addEventListener('change', onGrade);
  selects.sub.addEventListener('change', onSub);
  selects.top.addEventListener('change', onTop);
  selects.test.addEventListener('change', () => { state.sel.testId = selects.test.value; updateApply(); });

  $('durationSeg').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-v]');
    if (!btn) return;
    state.duration = Number(btn.dataset.v);
    $('durationSeg').querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
    if (state.sel.testId) updateApply();
  });

  function setDuration(v) {
    state.duration = v;
    $('durationSeg').querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(Number(b.dataset.v) === v)));
  }

  $('applyBtn').addEventListener('click', () => {
    if (!state.sel.testId) return;
    emit('host_select_category', {
      selectedPath: state.sel,
      settings: {
        questionDuration: state.duration,
        autoFinish: $('optAutoFinish').checked,
        autoSkipLeaderboard: $('optAutoSkip').checked
      }
    });
  });

  /* ─── Players ─── */
  function renderPlayers(list) {
    state.players = list;
    const grid = $('playerGrid');
    const existing = new Map(Array.from(grid.children).map((c) => [c.dataset.id, c]));
    const keep = new Set();

    list.forEach((p) => {
      keep.add(p.id);
      let chip = existing.get(p.id);
      if (!chip) {
        const kick = el('button', { type: 'button', class: 'kick', 'aria-label': `${p.nickname} adlı oyuncuyu çıkar` }, [icon('x', 'icon-sm')]);
        kick.addEventListener('click', () => askKick(p.id, p.nickname));
        chip = el('div', { class: 'player-chip', 'data-id': p.id }, [
          el('span', { class: 'avatar', text: initials(p.nickname), style: { '--av': avatarColor(p.nickname) } }),
          el('span', { text: p.nickname }),
          kick
        ]);
        chip.querySelector('.avatar').style.setProperty('--av', avatarColor(p.nickname));
        grid.appendChild(chip);
      }
      chip.classList.toggle('offline', p.online === false);
    });
    existing.forEach((chip, id) => { if (!keep.has(id)) chip.remove(); });

    const n = list.length;
    $('countTop').textContent = n;
    $('countLobby').textContent = n;
    $('emptyPlayers').hidden = n > 0;
    $('startBtn').disabled = n === 0;
    setButton($('startBtn'), 'play', n ? `Oyunu başlat · ${n}` : 'Oyunu başlat');
  }

  function askKick(id, name) {
    state.kickId = id;
    $('kickName').textContent = name;
    openDialog('kickDialog');
  }
  $('kickCancel').addEventListener('click', () => closeDialog('kickDialog'));
  $('kickConfirm').addEventListener('click', () => {
    if (state.kickId) emit('host_kick_player', { playerId: state.kickId });
    state.kickId = null;
    closeDialog('kickDialog');
  });

  /* ─── Game flow ─── */
  $('startBtn').addEventListener('click', () => emit('host_next_question'));
  $('skipBtn').addEventListener('click', () => emit('host_skip_timer'));
  $('boardBtn').addEventListener('click', () => {
    if (state.isLast) emit('host_end_game');
    else emit('host_show_leaderboard');
  });
  $('nextBtn').addEventListener('click', () => emit('host_next_question'));
  $('endBtn').addEventListener('click', () => emit('host_end_game'));
  $('newGameBtn').addEventListener('click', () => {
    clearSession();
    location.reload();
  });

  function showQuestion(d) {
    state.qDuration = d.duration;
    state.isLast = d.questionIndex + 1 >= d.totalQuestions;
    $('qNum').textContent = `Soru ${d.questionIndex + 1} / ${d.totalQuestions}`;
    $('qCat').textContent = d.categoryName || '';
    $('qProgress').style.width = `${((d.questionIndex + 1) / d.totalQuestions) * 100}%`;
    $('qText').textContent = d.q;
    $('qAnswered').textContent = d.answeredCount || 0;
    $('qTotal').textContent = d.totalPlayers;
    setTimer($('hTimer'), d.remaining != null ? d.remaining : d.duration, d.duration);

    const options = $('options');
    options.classList.remove('revealed');
    LETTERS.forEach((L) => {
      $('o' + L).textContent = (d.options && d.options[L]) || '—';
      $('b' + L).style.width = '0';
      options.querySelector(`[data-opt="${L}"]`).classList.remove('is-correct', 'is-wrong');
    });
    [$('qText'), ...options.children].forEach((n) => {
      n.style.animation = 'none';
      void n.offsetWidth;
      n.style.animation = '';
    });
    $('skipBtn').hidden = false;
    $('boardBtn').hidden = true;
    show('hQuestion');
  }

  function revealResult(d) {
    setTimer($('hTimer'), 0, state.qDuration);
    const options = $('options');
    options.classList.add('revealed');
    const max = Math.max(1, ...LETTERS.map((L) => d.distribution[L] || 0));
    LETTERS.forEach((L, i) => {
      const count = d.distribution[L] || 0;
      $('s' + L).textContent = count;
      options.querySelector(`[data-opt="${L}"]`).classList.add(L === d.correct ? 'is-correct' : 'is-wrong');
      setTimeout(() => { $('b' + L).style.width = `${(count / max) * 100}%`; }, 120 + i * 80);
    });
    state.isLast = !!d.isLast || state.isLast;
    $('skipBtn').hidden = true;
    $('boardBtn').hidden = false;
    setButton($('boardBtn'), state.isLast ? 'crown' : 'trophy', state.isLast ? 'Kürsüye geç' : 'Skor tablosu');
    $('boardBtn').focus();
  }

  function renderBoard(d) {
    $('boardEyebrow').textContent = `Soru ${d.questionIndex} / ${d.totalQuestions} sonrası`;
    const rows = d.leaderboard.map((p, i) => {
      const score = el('span', { class: 'board-score mono', text: '0' });
      const row = el('li', { class: 'board-row', style: { '--i': i } }, [
        el('span', { class: 'board-rank mono', text: String(i + 1) }),
        el('span', { class: 'board-name', text: p.nickname }),
        p.lastEarned > 0 ? el('span', { class: 'board-delta mono', text: `+${p.lastEarned}` }) : null,
        score
      ]);
      row.style.setProperty('--i', i);
      setTimeout(() => countUp(score, p.score, 900), 200 + i * 90);
      return row;
    });
    $('boardList').replaceChildren(...rows);

    const last = d.questionIndex >= d.totalQuestions;
    setButton($('nextBtn'), last ? 'crown' : 'arrow-right', last ? 'Kürsüye geç' : 'Sonraki soru');

    const bar = $('autoSkipBar');
    bar.hidden = !d.autoSkipMs;
    if (d.autoSkipMs) {
      const inner = bar.firstElementChild;
      inner.style.setProperty('--dur', `${d.autoSkipMs / 1000}s`);
      inner.style.animation = 'none';
      void inner.offsetWidth;
      inner.style.animation = '';
    }
    show('hBoard');
  }

  function renderPodium(d) {
    [1, 2, 3].forEach((n) => {
      const p = d.podium[n - 1];
      const step = document.querySelector(`.step-${n}`);
      step.classList.toggle('empty-step', !p);
      if (!p) return;
      $('pName' + n).textContent = p.nickname;
      $('pAv' + n).textContent = initials(p.nickname);
      $('pScore' + n).textContent = `${p.score.toLocaleString('tr-TR')} puan`;
    });
    const rest = (d.leaderboard || []).slice(3).map((p, i) => {
      const li = el('li', {}, [
        el('span', {}, [el('span', { class: 'mono', text: `#${i + 4}` }), document.createTextNode(p.nickname)]),
        el('span', { class: 'mono', text: p.score.toLocaleString('tr-TR') })
      ]);
      li.style.setProperty('--i', i);
      return li;
    });
    $('restList').replaceChildren(...rest);
    show('hPodium');
    setTimeout(() => confetti({ count: 220, duration: 5200 }), 1700);
    clearSession();
  }

  /* ─── Socket ─── */
  function connect() {
    const socket = io({ transports: ['websocket', 'polling'], reconnectionDelayMax: 4000 });
    state.socket = socket;

    socket.on('connect', () => {
      setConn(true, 'Canlı');
      socket.emit('host_join_room', { pin: state.pin, hostToken: state.token });
    });
    socket.on('disconnect', (reason) => {
      setConn(false, 'Yeniden bağlanıyor');
      if (reason !== 'io server disconnect') toast('Bağlantı koptu, yeniden bağlanılıyor…', 'error');
    });
    socket.on('connect_error', () => setConn(false, 'Bağlantı yok'));

    socket.on('auth_error', () => {
      clearSession();
      socket.disconnect();
      createRoom();
    });
    socket.on('error_msg', (m) => toast(m, 'error'));

    socket.on('host_connected', (d) => {
      state.db = d.categories || {};
      initBank(d.selectedPath);
      if (d.settings) {
        setDuration(d.settings.questionDuration);
        $('optAutoFinish').checked = d.settings.autoFinish;
        $('optAutoSkip').checked = d.settings.autoSkipLeaderboard;
      }
      $('activeTest').textContent = `${d.categoryName} · ${d.questionCount} soru`;
      renderPlayers(d.players || []);
      if (d.state === 'LOBBY') show('hLobby');
      else if (d.state === 'PODIUM') { clearSession(); show('hLobby'); }
    });

    socket.on('host_category_updated', (d) => {
      $('activeTest').textContent = `${d.categoryName} · ${d.questionCount} soru`;
      toast('Test uygulandı', 'ok');
    });

    socket.on('player_list_updated', (d) => renderPlayers(d.players || []));
    socket.on('host_show_question', showQuestion);
    socket.on('timer_tick', (d) => setTimer($('hTimer'), d.remainingSeconds, state.qDuration));
    socket.on('host_answer_update', (d) => {
      $('qAnswered').textContent = d.answeredCount;
      $('qTotal').textContent = d.totalPlayers;
    });
    socket.on('host_question_result', revealResult);
    socket.on('host_leaderboard_view', renderBoard);
    socket.on('host_game_over', renderPodium);
    socket.on('room_closed', (d) => {
      clearSession();
      toast((d && d.message) || 'Oda kapandı', 'error');
      socket.disconnect();
      setConn(false, 'Kapalı');
    });
  }

  async function createRoom() {
    try {
      const res = await fetch('/api/rooms', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const d = await res.json().catch(() => ({}));
      if (!d.success) {
        setConn(false, 'Hata');
        toast(d.error || 'Oda oluşturulamadı', 'error');
        return;
      }
      state.pin = d.pin;
      state.token = d.hostToken;
      saveSession();
      setupPin();
      connect();
    } catch (e) {
      setConn(false, 'Sunucu yok');
      toast('Sunucuya ulaşılamadı', 'error');
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const saved = loadSession();
    if (saved && /^\d{6}$/.test(saved.pin) && saved.token) {
      state.pin = saved.pin;
      state.token = saved.token;
      setupPin();
      connect();
    } else {
      createRoom();
    }
  });
})();
