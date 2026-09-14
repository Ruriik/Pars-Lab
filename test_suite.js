/**
 * PARS LAB - INTEGRATION & ZERO-TRUST SECURITY TEST SUITE
 */

const io = require('socket.io-client');
const http = require('http');

async function runTests() {
  console.log('>>> STARTING PARS LAB TEST SUITE <<<');
  const BASE_URL = 'http://localhost:3458';

  // 1. Test Room Creation via API with Cloudflare Header
  console.log('\n[TEST 1] Room creation with Cloudflare IP header...');
  const roomRes = await fetch(`${BASE_URL}/api/rooms`, {
    method: 'POST',
    headers: {
      'CF-Connecting-IP': '198.51.100.42',
      'Content-Type': 'application/json'
    }
  });
  const roomData = await roomRes.json();
  if (!roomData.success || !roomData.pin) {
    throw new Error('Room creation failed: ' + JSON.stringify(roomData));
  }
  const PIN = roomData.pin;
  console.log(`✓ Room created successfully! PIN: ${PIN}`);

  // 2. Test Failed PIN 10-Attempt Ban
  console.log('\n[TEST 2] Testing Failed PIN Attempts & IP Ban (OWASP)...');
  const attackerIp = '203.0.113.99';
  for (let i = 1; i <= 10; i++) {
    const checkRes = await fetch(`${BASE_URL}/api/check-pin`, {
      method: 'POST',
      headers: {
        'CF-Connecting-IP': attackerIp,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ pin: '000000' })
    });
    const checkData = await checkRes.json();
    if (i === 10) {
      console.log(`10th attempt status: ${checkRes.status}, body:`, checkData);
    }
  }
  // 11th attempt must be 429 BANNED
  const bannedRes = await fetch(`${BASE_URL}/api/check-pin`, {
    method: 'POST',
    headers: {
      'CF-Connecting-IP': attackerIp,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ pin: PIN }) // Even valid PIN should be blocked for banned IP
  });
  const bannedData = await bannedRes.json();
  console.log(`11th attempt from banned IP status: ${bannedRes.status}, body:`, bannedData);
  if (bannedRes.status !== 429 || !bannedData.banned) {
    throw new Error('IP Ban failed! Expected 429 with banned: true');
  }
  console.log('✓ IP ban successfully triggered after 10 failed attempts!');

  // 3. Test Host & Player Sockets, Game Flow & Zero-Trust Payloads
  console.log('\n[TEST 3] Socket Connections & Zero-Trust Payload Verification...');

  const hostSocket = io(BASE_URL, {
    extraHeaders: { 'CF-Connecting-IP': '198.51.100.42' }
  });

  const playerSocket = io(BASE_URL, {
    extraHeaders: { 'CF-Connecting-IP': '198.51.100.43' }
  });

  await new Promise((resolve) => hostSocket.on('connect', resolve));
  await new Promise((resolve) => playerSocket.on('connect', resolve));
  console.log('✓ Host and Player sockets connected.');

  // Host registers to room
  hostSocket.emit('host_join_room', { pin: PIN });
  await new Promise((resolve) => {
    hostSocket.on('host_connected', (data) => {
      if (data.pin === PIN) resolve();
    });
  });
  console.log('✓ Host joined room successfully.');

  // Player joins room
  playerSocket.emit('player_join_room', { pin: PIN, nickname: 'HackerPars' });
  await new Promise((resolve) => {
    playerSocket.on('player_joined', (data) => {
      if (data.nickname === 'HackerPars') resolve();
    });
  });
  console.log('✓ Player joined room successfully.');

  // 4. Test Access Control: Non-host trying to start question
  console.log('\n[TEST 4] Testing Access Control (Player attempting host action)...');
  playerSocket.emit('host_next_question', { pin: PIN });
  const accessError = await new Promise((resolve) => {
    playerSocket.on('error_msg', (msg) => resolve(msg));
  });
  console.log(`Player received error: "${accessError}"`);
  if (!accessError.includes('yalnızca Host') && !accessError.includes('Sadece Host')) {
    throw new Error('Access control check failed!');
  }
  console.log('✓ Access control correctly blocked non-host action!');

  // 5. Host Starts Question 1 -> Verify Zero-Trust Payloads
  console.log('\n[TEST 5] Verifying Question Payloads (Zero-Trust vs Host)...');

  let hostQuestionPayload = null;
  let playerQuestionPayload = null;

  const questionPromises = Promise.all([
    new Promise((resolve) => {
      hostSocket.on('host_show_question', (data) => {
        hostQuestionPayload = data;
        resolve();
      });
    }),
    new Promise((resolve) => {
      playerSocket.on('player_show_buttons', (data) => {
        playerQuestionPayload = data;
        resolve();
      });
    })
  ]);

  hostSocket.emit('host_next_question', { pin: PIN });
  await questionPromises;

  console.log('Host received question:', hostQuestionPayload.q);
  console.log('Host options available:', Object.keys(hostQuestionPayload.options));
  if (hostQuestionPayload.correct !== undefined) {
    throw new Error('Security Breach: Host received correct answer before question end!');
  }

  console.log('Mobile Player received payload:', playerQuestionPayload);

  // CRITICAL ZERO-TRUST VALIDATION:
  if (playerQuestionPayload.q !== undefined ||
      playerQuestionPayload.options !== undefined ||
      playerQuestionPayload.correct !== undefined) {
    throw new Error('CRITICAL ZERO-TRUST BREACH: Mobile client received question or options payload!');
  }
  if (playerQuestionPayload.action !== 'show_buttons') {
    throw new Error('Expected player action: "show_buttons"');
  }
  console.log('✓ ZERO-TRUST VERIFIED: Mobile client received ONLY action: "show_buttons" with NO text/options!');

  // 6. Test Player Submits Answer
  console.log('\n[TEST 6] Testing Player Answer Submission & Scoring...');
  playerSocket.emit('player_submit_answer', { pin: PIN, answer: 'B' }); // Istanbul'un fethi -> 1453 (B)

  await new Promise((resolve) => {
    playerSocket.on('player_answer_received', (data) => {
      if (data.selectedAnswer === 'B') resolve();
    });
  });
  console.log('✓ Answer submission acknowledged.');

  // Wait for result event (since 1 player in room, answer automatically finishes question!)
  const [playerResult, hostResult] = await Promise.all([
    new Promise((resolve) => playerSocket.on('player_question_result', resolve)),
    new Promise((resolve) => hostSocket.on('host_question_result', resolve))
  ]);

  console.log('Player Question Result:', playerResult);
  console.log('Host Question Result:', hostResult);

  if (!playerResult.isCorrect || playerResult.earnedPoints <= 0) {
    throw new Error('Scoring failure: Expected correct answer with positive points!');
  }
  if (playerResult.q !== undefined || playerResult.options !== undefined) {
    throw new Error('Zero trust breach in result payload!');
  }
  if (hostResult.correct !== 'B') {
    throw new Error('Host result wrong answer');
  }
  console.log(`✓ Player earned ${playerResult.earnedPoints} points!`);

  // Disconnect
  hostSocket.disconnect();
  playerSocket.disconnect();

  console.log('\n===========================================');
  console.log('ALL ZERO-TRUST & SECURITY TESTS PASSED! 🎉');
  console.log('===========================================');
  process.exit(0);
}

// Start server on 3458 and run
process.env.PORT = 3458;
require('./server.js');
setTimeout(runTests, 1000);
