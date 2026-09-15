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

// 5. MODULAR 9-10TH GRADE QUESTION PACKS STORED IN BACKEND RAM (20 QUESTIONS PER CATEGORY)
const QUESTION_CATEGORIES = {
  siber_guvenlik: {
    id: 'siber_guvenlik',
    name: 'Siber Güvenlik',
    badge: 'CYBER-SEC',
    description: 'OSI modeli, TCP/IP, Ağ güvenliği ve Zararlı yazılımlar',
    questions: [
      {
        q: "OSI referans modelinde verinin şifrelenmesi ve sıkıştırılmasından sorumlu olan katman hangisidir?",
        options: { A: "Sunum Katmanı (Presentation)", B: "Ağ Katmanı (Network)", C: "Taşıma Katmanı (Transport)", D: "Fiziksel Katman (Physical)" },
        correct: "A"
      },
      {
        q: "Bir sistemdeki dosyaları şifreleyerek erişilemez kılan ve açmak için fidye talep eden zararlı yazılım türü hangisidir?",
        options: { A: "Spyware (Casus Yazılım)", B: "Ransomware (Fidye Yazılımı)", C: "Adware (Reklam Yazılımı)", D: "Worm (Solucan)" },
        correct: "B"
      },
      {
        q: "Web siteleri ile istemciler arasındaki veri trafiğini şifreleyerek güvenli kılan protokol hangisidir?",
        options: { A: "HTTP", B: "FTP", C: "HTTPS", D: "Telnet" },
        correct: "C"
      },
      {
        q: "TCP ve UDP protokolleri OSI referans modelinin hangi katmanında görev yapar?",
        options: { A: "Taşıma Katmanı (Transport)", B: "Veri Bağlantısı Katmanı (Data Link)", C: "Ağ Katmanı (Network)", D: "Oturum Katmanı (Session)" },
        correct: "A"
      },
      {
        q: "Kullanıcıları sahte web sitelerine yönlendirerek hesap şifresi veya kimlik bilgilerini çalmayı amaçlayan sosyal mühendislik saldırısı nedir?",
        options: { A: "DDoS Saldırısı", B: "Phishing (Oltalama)", C: "SQL Injection", D: "Man-in-the-Middle" },
        correct: "B"
      },
      {
        q: "Bir şifreyi ele geçirmek için olası tüm karakter kombinasyonlarını sırayla deneyen saldırı yöntemi hangisidir?",
        options: { A: "Brute Force (Kaba Kuvvet)", B: "XSS Saldırısı", C: "DNS Zehirleme", D: "Session Hijacking" },
        correct: "A"
      },
      {
        q: "Ağ trafiğini denetleyerek kurallara göre yetkisiz girişleri ve siber tehditleri engelleyen güvenlik mekanizması hangisidir?",
        options: { A: "Modem", B: "Firewall (Güvenlik Duvarı)", C: "Switch (Anahtar)", D: "Repeater (Yineleyici)" },
        correct: "B"
      },
      {
        q: "Klavyede basılan her bir tuş vuruşunu gizlice kaydedip saldırgana ileten casus yazılım türü hangisidir?",
        options: { A: "Keylogger", B: "Rootkit", C: "Worm", D: "Trojan" },
        correct: "A"
      },
      {
        q: "Dağıtık Hizmet Engelleme (DDoS) saldırısının temel amacı aşağıdakilerden hangisidir?",
        options: { A: "Sunucuya aşırı yük bindirerek sistemi erişilemez hale getirmek", B: "Veritabanındaki kullanıcı şifrelerini çalmak", C: "Sunucuya fiziksel olarak hasar vermek", D: "Web sitesinin tasarımını değiştirmek" },
        correct: "A"
      },
      {
        q: "Alan adlarını (örn: pars.meb.gov.tr) IP adreslerine dönüştürerek iletişimi sağlayan sistem hangisidir?",
        options: { A: "FTP", B: "DNS", C: "DHCP", D: "SMTP" },
        correct: "B"
      },
      {
        q: "Yararlı ve güvenli bir program gibi görünen ancak arka planda gizlice zararlı işler yürüten yazılım türü nedir?",
        options: { A: "Solucan (Worm)", B: "Truva Atı (Trojan)", C: "Casus Yazılım (Spyware)", D: "Reklam Yazılımı (Adware)" },
        correct: "B"
      },
      {
        q: "İnternet trafiğini şifreleyip güvenli sanal bir tünel oluşturarak çevrimiçi gizlilik sağlayan teknoloji hangisidir?",
        options: { A: "VPN", B: "VLAN", C: "VoIP", D: "NAT" },
        correct: "A"
      },
      {
        q: "Saldırganın, haberleşen iki tarafın arasına gizlice girerek iletişimi dinlemesi veya değiştirmesi saldırısı nedir?",
        options: { A: "Brute Force", B: "SQL Injection", C: "Man-in-the-Middle (MitM)", D: "Buffer Overflow" },
        correct: "C"
      },
      {
        q: "İki faktörlü kimlik doğrulamanın (2FA) temel amacı nedir?",
        options: { A: "Şifre uzunluğunu kısaltmak", B: "Şifreye ek ikinci bir doğrulama katmanı ile güvenliği artırmak", C: "İnternet bağlantısını hızlandırmak", D: "Kullanıcı adını gizlemek" },
        correct: "B"
      },
      {
        q: "Yazılım üreticisinin henüz fark etmediği ve yaması bulunmayan güvenlik açıklarını hedef alan saldırılara ne denir?",
        options: { A: "Zero-Day (Sıfır Gün) Saldırısı", B: "Sözlük Saldırısı", C: "Oltalama Saldırısı", D: "Kaba Kuvvet Saldırısı" },
        correct: "A"
      },
      {
        q: "Kullanıcının izni olmadan sürekli reklam gösteren ve tarayıcı davranışlarını izleyebilen yazılım türü hangisidir?",
        options: { A: "Rootkit", B: "Adware", C: "Ransomware", D: "Backdoor" },
        correct: "B"
      },
      {
        q: "Bir ağdaki veri paketlerini dinleyerek şifrelenmemiş hassas bilgileri yakalama işlemine ne ad verilir?",
        options: { A: "Sniffing (Paket Koklama)", B: "Spoofing (Aldatma)", C: "Pinging", D: "Traceroute" },
        correct: "A"
      },
      {
        q: "Güçlü bir şifre oluştururken aşağıdakilerden hangisinden kesinlikle KAÇINILMALIDIR?",
        options: { A: "Büyük ve küçük harf karışımı kullanmaktan", B: "Doğum tarihi ve isim gibi tahmin edilebilir kişisel verilerden", C: "Rakamlar ve özel semboller eklemekten", D: "En az 12-16 karakter uzunluk belirlemekten" },
        correct: "B"
      },
      {
        q: "Şifrelenmiş verinin yetkili anahtar kullanılarak orijinal haline dönüştürülmesi işlemine ne ad verilir?",
        options: { A: "Hashing", B: "Encoding", C: "Deşifreleme (Decryption)", D: "Derleme (Compilation)" },
        correct: "C"
      },
      {
        q: "Kötü niyetli kişilerin kontrolüne geçmiş ve genellikle DDoS saldırılarında kullanılan ele geçirilmiş bilgisayar ağına ne denir?",
        options: { A: "Intranet", B: "Botnet", C: "Darknet", D: "Ethernet" },
        correct: "B"
      }
    ]
  },
  yazilim_gelistirme: {
    id: 'yazilim_gelistirme',
    name: 'Yazılım Geliştirme',
    badge: 'DEV-CODE',
    description: 'HTML etiketleri, Algoritmalar, Değişkenler ve Programlama',
    questions: [
      {
        q: "HTML belgesinde başka bir web sayfasına köprü (link) oluşturmak için hangi etiket kullanılır?",
        options: { A: "<link>", B: "<a>", C: "<href>", D: "<nav>" },
        correct: "B"
      },
      {
        q: "Belirli bir koşul sağlandığı sürece komut bloklarının tekrarlanmasını sağlayan algoritma yapısı hangisidir?",
        options: { A: "Döngü (Loop)", B: "Değişken (Variable)", C: "Fonksiyon (Function)", D: "Dizi (Array)" },
        correct: "A"
      },
      {
        q: "Python programlama dilinde terminal ekranına veri yazdırmak için kullanılan temel fonksiyon hangisidir?",
        options: { A: "console.log()", B: "echo()", C: "print()", D: "write()" },
        correct: "C"
      },
      {
        q: "Bir problemin çözüm adımlarını geometrik şekiller ve yön oklarıyla görselleştiren şemaya ne ad verilir?",
        options: { A: "Akış Şeması (Flowchart)", B: "Sözde Kod (Pseudocode)", C: "Mantık Tablosu", D: "Venn Şeması" },
        correct: "A"
      },
      {
        q: "Web sayfalarının görsel tasarımını, renklerini, yazı tiplerini ve yerleşimini düzenleyen teknoloji hangisidir?",
        options: { A: "SQL", B: "CSS", C: "XML", D: "JSON" },
        correct: "B"
      },
      {
        q: "HTML dokümanında en büyük ve en önemli başlığı tanımlayan etiket hangisidir?",
        options: { A: "<head>", B: "<h6>", C: "<h1>", D: "<title>" },
        correct: "C"
      },
      {
        q: "Programlamada mantıksal şartlara göre farklı kod bloklarının çalıştırılmasını sağlayan kontrol yapısı hangisidir?",
        options: { A: "if - else", B: "for - in", C: "while", D: "try - catch" },
        correct: "A"
      },
      {
        q: "Sadece \"True\" (Doğru) veya \"False\" (Yanlış) olmak üzere iki değer alabilen veri türü hangisidir?",
        options: { A: "String", B: "Boolean", C: "Float", D: "Integer" },
        correct: "B"
      },
      {
        q: "Python'da kod satırına tek satırlık açıklama (yorum) eklemek için hangi karakter kullanılır?",
        options: { A: "//", B: "/*", C: "#", D: "--" },
        correct: "C"
      },
      {
        q: "Birden fazla veriyi tek bir değişken altında sıralı bir biçimde saklamaya yarayan veri yapısı hangisidir?",
        options: { A: "Değişken", B: "Dizi (Array / List)", C: "Operatör", D: "Sabit (Constant)" },
        correct: "B"
      },
      {
        q: "Belirli bir görevi yerine getiren ve programın farklı yerlerinden tekrar tekrar çağrılabilen kod bloklarına ne ad verilir?",
        options: { A: "Fonksiyon (Function)", B: "Döngü", C: "Koşul", D: "Kütüphane" },
        correct: "A"
      },
      {
        q: "Web tarayıcılarında çalışan ve web sayfalarına dinamik etkileşim kazandıran programlama dili hangisidir?",
        options: { A: "Python", B: "JavaScript", C: "SQL", D: "C++" },
        correct: "B"
      },
      {
        q: "Bir programlama dilinin yazım kurallarına uyulmadığında ortaya çıkan hata türüne ne denir?",
        options: { A: "Mantık Hatası", B: "Sözdizimi Hatası (Syntax Error)", C: "Bellek Taşması", D: "Çalışma Zamanı Hatası" },
        correct: "B"
      },
      {
        q: "HTML'de sırasız (madde işaretli) bir liste oluşturmak için kullanılan etiket hangisidir?",
        options: { A: "<ol>", B: "<ul>", C: "<li>", D: "<dl>" },
        correct: "B"
      },
      {
        q: "Python programlama dilinde kullanıcıdan klavye ile girdi almak için kullanılan fonksiyon hangisidir?",
        options: { A: "input()", B: "get()", C: "read()", D: "scan()" },
        correct: "A"
      },
      {
        q: "C, Java ve JavaScript gibi dillerde bir sayısal değişkenin değerini 1 artırmak için hangi operatör kullanılır?",
        options: { A: "++", B: "**", C: "+=", D: "==" },
        correct: "A"
      },
      {
        q: "Bir web sayfasına görsel (resim) eklemek için kullanılan HTML etiketi hangisidir?",
        options: { A: "<image>", B: "<picture>", C: "<img>", D: "<src>" },
        correct: "C"
      },
      {
        q: "İlişkisel veritabanlarından veri sorgulamak, eklemek ve güncellemek için kullanılan standart dil hangisidir?",
        options: { A: "JSON", B: "SQL", C: "HTML", D: "XML" },
        correct: "B"
      },
      {
        q: "Yazılım geliştirmede kod değişikliklerini adım adım kaydetmeye ve sürümleri yönetmeye yarayan sistem hangisidir?",
        options: { A: "Git", B: "Docker", C: "Apache", D: "Nginx" },
        correct: "A"
      },
      {
        q: "Bir algoritmanın adım adım ilerleyerek sonlu sayıda işlem sonucunda mutlaka tamamlanması özelliğine ne denir?",
        options: { A: "Sonsuzluk", B: "Sonluluk", C: "Kesinlik", D: "Karmaşıklık" },
        correct: "B"
      }
    ]
  },
  genel_kultur: {
    id: 'genel_kultur',
    name: 'Genel Kültür',
    badge: 'GEN-KNOW',
    description: 'Tarih, Bilim, Coğrafya ve Temel Bilgiler',
    questions: [
      {
        q: "İstanbul'un fethinin gerçekleştiği yıl hangisidir?",
        options: { A: "1451", B: "1453", C: "1461", D: "1517" },
        correct: "B"
      },
      {
        q: "İstiklal Marşı'mızın şairi kimdir?",
        options: { A: "Namık Kemal", B: "Mehmet Akif Ersoy", C: "Ziya Gökalp", D: "Yahya Kemal" },
        correct: "B"
      },
      {
        q: "Türkiye Büyük Millet Meclisi hangi tarihte açılmıştır?",
        options: { A: "19 Mayıs 1919", B: "23 Nisan 1920", C: "29 Ekim 1923", D: "30 Ağustos 1922" },
        correct: "B"
      },
      {
        q: "Periyodik tablonun birinci elementi hangisidir?",
        options: { A: "Helyum", B: "Lityum", C: "Karbon", D: "Hidrojen" },
        correct: "D"
      },
      {
        q: "Cumhuriyet hangi tarihte ilan edilmiştir?",
        options: { A: "23 Nisan 1920", B: "29 Ekim 1923", C: "30 Ağustos 1922", D: "19 Mayıs 1919" },
        correct: "B"
      },
      {
        q: "Hücrenin enerji santrali olarak bilinen organeli hangisidir?",
        options: { A: "Ribozom", B: "Lizozom", C: "Mitokondri", D: "Çekirdek" },
        correct: "C"
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
        q: "Güneş sistemindeki en büyük gezegen hangisidir?",
        options: { A: "Mars", B: "Venüs", C: "Satürn", D: "Jüpiter" },
        correct: "D"
      },
      {
        q: "\"Suç ve Ceza\" adlı dünyaca ünlü eserin yazarı kimdir?",
        options: { A: "Tolstoy", B: "Dostoyevski", C: "Puşkin", D: "Gogol" },
        correct: "B"
      },
      {
        q: "Dünyanın en uzun nehri aşağıdakilerden hangisidir?",
        options: { A: "Amazon", B: "Nil", C: "Mississippi", D: "Tuna" },
        correct: "B"
      },
      {
        q: "Fransız İhtilali hangi yılda başlamıştır?",
        options: { A: "1776", B: "1789", C: "1830", D: "1848" },
        correct: "B"
      },
      {
        q: "Işık hızı boşlukta saniyede yaklaşık kaç kilometredir?",
        options: { A: "100.000", B: "200.000", C: "300.000", D: "400.000" },
        correct: "C"
      },
      {
        q: "Anadolu'nun kapılarını Türklere açan Malazgirt Meydan Muharebesi hangi tarihte gerçekleşmiştir?",
        options: { A: "1048", B: "1071", C: "1176", D: "1299" },
        correct: "B"
      },
      {
        q: "Türkiye'nin yüzölçümü bakımından en büyük gölü hangisidir?",
        options: { A: "Tuz Gölü", B: "Beyşehir Gölü", C: "Van Gölü", D: "Eğirdir Gölü" },
        correct: "C"
      },
      {
        q: "Birinci Dünya Savaşı hangi yıllar arasında gerçekleşmiştir?",
        options: { A: "1912-1913", B: "1914-1918", C: "1939-1945", D: "1919-1922" },
        correct: "B"
      },
      {
        q: "Türk edebiyatının unutulmaz eseri \"Hababam Sınıfı\"nın yazarı kimdir?",
        options: { A: "Aziz Nesin", B: "Rıfat Ilgaz", C: "Sabahattin Ali", D: "Orhan Veli" },
        correct: "B"
      },
      {
        q: "Genetik bilginin taşıyıcısı olan DNA'nın açılımı nedir?",
        options: { A: "Dinamik Nükleik Asit", B: "Deoksiribo Nükleik Asit", C: "Çift Sarmal Asit", D: "Deoksi Nitro Asit" },
        correct: "B"
      },
      {
        q: "Evrensel yerçekimi kanununu formüle eden ünlü bilim insanı kimdir?",
        options: { A: "Albert Einstein", B: "Isaac Newton", C: "Galileo Galilei", D: "Nikola Tesla" },
        correct: "B"
      },
      {
        q: "Dünyaca ünlü Mona Lisa tablosu hangi İtalyan sanatçıya aittir?",
        options: { A: "Michelangelo", B: "Raphael", C: "Leonardo da Vinci", D: "Donatello" },
        correct: "C"
      }
    ]
  },
  ingilizce: {
    id: 'ingilizce',
    name: 'İngilizce',
    badge: 'ENG-LANG',
    description: 'Temel gramer, günlük konuşma kalıpları ve kelime bilgisi',
    questions: [
      {
        q: "\"She ______ to school by bus every morning.\" cümlesindeki boşluğa hangisi gelmelidir?",
        options: { A: "go", B: "goes", C: "going", D: "is go" },
        correct: "B"
      },
      {
        q: "\"What is your father's profession?\" sorusuna verilebilecek en uygun yanıt hangisidir?",
        options: { A: "He is fifty years old", B: "He is an engineer", C: "He lives in Ankara", D: "He likes playing chess" },
        correct: "B"
      },
      {
        q: "\"I haven't seen you for a long time!\" ifadesinin Türkçe karşılığı hangisidir?",
        options: { A: "Seni uzun zamandır görmedim!", B: "Nerede olduğunu bilmiyorum!", C: "Görüşmeyeli çok zaman oldu mu?", D: "Zaman çabuk geçiyor!" },
        correct: "A"
      },
      {
        q: "\"Look at the dark clouds! It ______ rain.\" cümlesindeki tahmini en doğru tamamlayan ifade hangisidir?",
        options: { A: "is going to", B: "will to", C: "went", D: "has" },
        correct: "A"
      },
      {
        q: "\"Environment\" kelimesinin Türkçe anlamı aşağıdakilerden hangisidir?",
        options: { A: "Teknoloji", B: "Çevre", C: "Toplum", D: "Gelecek" },
        correct: "B"
      },
      {
        q: "\"He is very interested ______ learning computer programming.\" cümlesinde boşluğa hangi edat gelmelidir?",
        options: { A: "on", B: "at", C: "in", D: "with" },
        correct: "C"
      },
      {
        q: "\"Yesterday, we ______ an exciting football match on TV.\" cümlesini tamamlayan en uygun fiil hangisidir?",
        options: { A: "watch", B: "watched", C: "watching", D: "are watching" },
        correct: "B"
      },
      {
        q: "\"Success\" (Başarı) sözcüğünün zıt anlamlısı (antonym) aşağıdakilerden hangisidir?",
        options: { A: "Victory", B: "Failure", C: "Honor", D: "Goal" },
        correct: "B"
      },
      {
        q: "\"If it rains tomorrow, we ______ cancel the picnic.\" cümlesindeki boşluğa hangisi gelmelidir?",
        options: { A: "will", B: "would", C: "have", D: "did" },
        correct: "A"
      },
      {
        q: "\"Could you please open the window?\" cümlesi İngilizce iletişimde hangi amaçla kullanılır?",
        options: { A: "Polite Request (Kibar rica)", B: "Giving Advice (Tavsiye)", C: "Refusal (Reddetme)", D: "Apology (Özür)" },
        correct: "A"
      },
      {
        q: "\"This laptop is ______ than my old computer.\" cümlesinde boşluğa hangisi gelmelidir?",
        options: { A: "fast", B: "fastest", C: "faster", D: "more fast" },
        correct: "C"
      },
      {
        q: "\"Delicious\" (Lezzetli) kelimesinin eş anlamlısı (synonym) aşağıdakilerden hangisidir?",
        options: { A: "Bitter", B: "Tasty", C: "Salty", D: "Terrible" },
        correct: "B"
      },
      {
        q: "\"How ______ sugar do you put in your tea?\" cümlesindeki boşluğa hangisi gelmelidir?",
        options: { A: "many", B: "much", C: "few", D: "lot" },
        correct: "B"
      },
      {
        q: "\"They have lived in Istanbul ______ 2018.\" cümlesinde zaman bildiren boşluğa hangisi gelmelidir?",
        options: { A: "since", B: "for", C: "in", D: "ago" },
        correct: "A"
      },
      {
        q: "\"You ______ stop when the traffic light is red.\" kural bildiren cümleye hangisi gelmelidir?",
        options: { A: "must", B: "might", C: "can", D: "shall" },
        correct: "A"
      },
      {
        q: "\"What time do you usually wake up on weekdays?\" sorusuna verilecek en mantıklı cevap hangisidir?",
        options: { A: "Yes, I do", B: "At 7:00 AM", C: "By bus", D: "With my friend" },
        correct: "B"
      },
      {
        q: "\"Generous\" (Cömert) kelimesinin zıt anlamlısı aşağıdakilerden hangisidir?",
        options: { A: "Kind", B: "Stingy (Cimri)", C: "Helpful", D: "Polite" },
        correct: "B"
      },
      {
        q: "\"While I was reading a book, my brother ______ the door.\" cümlesine hangisi gelmelidir?",
        options: { A: "knocks", B: "knocked", C: "knocking", D: "is knock" },
        correct: "B"
      },
      {
        q: "\"The bookstore is located ______ the bank and the pharmacy.\" cümlesine hangisi gelmelidir?",
        options: { A: "between", B: "among", C: "under", D: "above" },
        correct: "A"
      },
      {
        q: "Günlük hayatta vedalaşırken söylenen \"Take care of yourself!\" ifadesinin Türkçe anlamı nedir?",
        options: { A: "Tebrik ederim!", B: "Kendine iyi bak!", C: "Geçmiş olsun!", D: "Hoşça kal deme!" },
        correct: "B"
      }
    ]
  },
  din_kulturu: {
    id: 'din_kulturu',
    name: 'Din Kültürü',
    badge: 'REL-CULT',
    description: 'Temel kavramlar, inanç esasları ve ibadetler',
    questions: [
      {
        q: "İslam dininde Allah'ın bir ve tek olduğuna, eşi ve benzeri bulunmadığına inanma ilkesine ne ad verilir?",
        options: { A: "Tevhid", B: "İhsan", C: "Nübüvvet", D: "Ahiret" },
        correct: "A"
      },
      {
        q: "Kur'an-ı Kerim'in indirilmeye başlandığı ve \"Bin aydan daha hayırlı\" olduğu belirtilen mübarek gece hangisidir?",
        options: { A: "Miraç Kandili", B: "Kadir Gecesi", C: "Regaip Kandili", D: "Berat Kandili" },
        correct: "B"
      },
      {
        q: "İslam'ın şartlarından olan ve belirli zenginlik ölçüsüne ulaşan Müslümanların yılda bir kez vermesi gereken malî ibadet hangisidir?",
        options: { A: "Sadaka", B: "Zekât", C: "Fitre", D: "Kurban" },
        correct: "B"
      },
      {
        q: "Peygamberlerin dürüst ve güvenilir olmalarını ifade eden sıfatı aşağıdakilerden hangisidir?",
        options: { A: "Emanet", B: "Fetanet", C: "İsmet", D: "Tebliğ" },
        correct: "A"
      },
      {
        q: "Sözlükte \"örtmek, inkâr etmek\" anlamına gelen, dinî olarak Allah'ın varlığını veya bildirdiği hakikatleri inkâr etmeyi ifade eden kavram nedir?",
        options: { A: "Nifak", B: "Küfür", C: "Fısk", D: "Gıybet" },
        correct: "B"
      },
      {
        q: "Peygamberlerin günah işlemekten korunmuş olduklarını ifade eden peygamberlik sıfatı hangisidir?",
        options: { A: "İsmet", B: "Fetanet", C: "Tebliğ", D: "Sıdk" },
        correct: "A"
      },
      {
        q: "İbadetlerin yalnızca Allah rızası için, samimiyetle ve gösterişten uzak yapılmasına ne ad verilir?",
        options: { A: "Takva", B: "İhlas", C: "İhsan", D: "Tevekkül" },
        correct: "B"
      },
      {
        q: "İslam'ın inanç esaslarını (imanın şartlarını) oluşturan temel rükünlerin sayısı kaçtır?",
        options: { A: "4", B: "5", C: "6", D: "7" },
        correct: "C"
      },
      {
        q: "Kur'an-ı Kerim'in ilk indirilen ayetleri (\"Yaratan Rabbinin adıyla oku!\") hangi surededir?",
        options: { A: "Fatiha Suresi", B: "Alak Suresi", C: "Bakara Suresi", D: "İhlas Suresi" },
        correct: "B"
      },
      {
        q: "Peygamber Efendimiz (s.a.v.)'e peygamberlik öncesi dönemde Mekkeliler tarafından verilen güvenilirlik unvanı hangisidir?",
        options: { A: "Halilullah", B: "Muhammedü'l-Emin", C: "Habibullah", D: "Seyfullah" },
        correct: "B"
      },
      {
        q: "İslam'da bir kimsenin zekât vermekle yükümlü sayılması için sahip olması gereken dinî zenginlik ölçüsüne ne denir?",
        options: { A: "Nisap", B: "Sadaka", C: "Öşür", D: "Fitre" },
        correct: "A"
      },
      {
        q: "Sözlükte \"ortak koşmak\" anlamına gelen ve Allah'tan başka varlıklara ilahlık yakıştırmayı ifade eden büyük günah hangisidir?",
        options: { A: "Fısk", B: "Şirk", C: "Nifak", D: "Gıybet" },
        correct: "B"
      },
      {
        q: "İnanmadığı halde diliyle inandığını söyleyen, iki yüzlü davranan kimselere İslam terminolojisinde ne ad verilir?",
        options: { A: "Müşrik", B: "Münafık", C: "Kâfir", D: "Fasık" },
        correct: "B"
      },
      {
        q: "Kur'an-ı Kerim'in durak işaretleriyle birbirinden ayrılan her bir cümlesine ne ad verilir?",
        options: { A: "Ayet", B: "Sure", C: "Cüz", D: "Mushaf" },
        correct: "A"
      },
      {
        q: "Kur'an-ı Kerim'de toplam kaç sure bulunmaktadır?",
        options: { A: "99", B: "114", C: "120", D: "666" },
        correct: "B"
      },
      {
        q: "Peygamberlerin peygamberliklerini kanıtlamak amacıyla Allah'ın izni ve yardımıyla gösterdikleri olağanüstü olaylara ne denir?",
        options: { A: "Keramet", B: "Mucize", C: "İlham", D: "Kehanet" },
        correct: "B"
      },
      {
        q: "İslam hukukunda dinin korunmasını hedeflediği \"can, akıl, mal, nesil ve din\" temel ilkelerine ne ad verilir?",
        options: { A: "Zarurat-ı Diniyye (Zarurat-ı Hamse)", B: "Farz-ı Kifaye", C: "Sünnet-i Müekkede", D: "Vacip" },
        correct: "A"
      },
      {
        q: "Dinen yapılması kesin delillerle ve açıkça yasaklanmış olan iş ve eylemlere ne ad verilir?",
        options: { A: "Mekruh", B: "Haram", C: "Mübah", D: "Şüpheli" },
        correct: "B"
      },
      {
        q: "İnsanın ölümüyle başlayan ve kıyametin kopup yeniden diriliş gerçekleşene kadar sürecek olan kabir hayatına ne ad verilir?",
        options: { A: "Mahşer", B: "Berzah", C: "Mizan", D: "Sırat" },
        correct: "B"
      },
      {
        q: "Peygamberlerin Allah'tan aldıkları vahiyleri insanlara hiçbir eksiltme veya ekleme yapmadan aynen ulaştırmalarına ne denir?",
        options: { A: "Tebliğ", B: "Sıdk", C: "Fetanet", D: "İsmet" },
        correct: "A"
      }
    ]
  },
  turkce: {
    id: 'turkce',
    name: 'Türkçe',
    badge: 'TR-LANG',
    description: 'Paragraf anlamı, deyimler, yazım kuralları ve noktalama',
    questions: [
      {
        q: "Aşağıdaki cümlelerin hangisinde \"-ki\" ekinin yazımıyla ilgili bir yazım yanlışı vardır?",
        options: { A: "Evdeki hesap çarşıya uymadı.", B: "Kitapta ki sorular oldukça zordu.", C: "Seninki yine ortalıkta görünmüyor.", D: "Mademki gelmeyecektin, haber verseydin." },
        correct: "B"
      },
      {
        q: "\"Bir kusuru iyi gibi göstererek birini aldatmak, yanıltmak\" anlamına gelen deyim hangisidir?",
        options: { A: "Göz boyamak", B: "Göze girmek", C: "Gözden düşmek", D: "Göz yummak" },
        correct: "A"
      },
      {
        q: "\"Yazar, eserlerinde günlük konuşma dilini ve halkın samimi duygularını ustaca yansıtmıştır.\" cümlesinde eserin hangi yönü vurgulanmıştır?",
        options: { A: "Üslubu (Biçemi)", B: "Özgünlüğü", C: "Evrenselliği", D: "Konusu" },
        correct: "A"
      },
      {
        q: "\"Sanatçı son eseriyle edebiyat dünyasında derin izler bıraktı.\" cümlesinde altı çizili sözle anlatılmak istenen nedir?",
        options: { A: "Kalıcı ve etkili olmak", B: "Çok sayıda kitap satmak", C: "Eleştirmenleri şaşırtmak", D: "Farklı türlerde eser vermek" },
        correct: "A"
      },
      {
        q: "Aşağıdaki cümlelerin hangisinde noktalama işareti YANLIŞ kullanılmıştır?",
        options: { A: "Pazardan elma, armut; marketten süt aldım.", B: "Ali; yarın bizimle geleceğini söyledi.", C: "Eyvah, cüzdanımı evde unuttum!", D: "23 Nisan 1920'de TBMM açıldı." },
        correct: "B"
      },
      {
        q: "Aşağıdaki cümlelerin hangisinde büyük harflerin yazımıyla ilgili bir yanlışlık yapılmıştır?",
        options: { A: "Yarın Boğaz Köprüsü'nden geçeceğiz.", B: "Bu yaz Van gölü çevresini gezdik.", C: "Türk Dil Kurumu 1932'de kuruldu.", D: "Kurtuluş Savaşı tarihi yeniden yazdı." },
        correct: "B"
      },
      {
        q: "Aşağıdaki cümlelerin hangisinde \"de/da\" bağlacının yazımıyla ilgili bir yanlışlık yapılmıştır?",
        options: { A: "Sen de bizimle sinemaya gel.", B: "Ev de unutulan çantayı hemen getirdi.", C: "Kitabın kapağında güzel bir resim var.", D: "Bu soruyu o da çözemedi." },
        correct: "B"
      },
      {
        q: "Çok öfkelenmek ve öfkesini sözleriyle çok sert bir biçimde dışa vurmak anlamına gelen deyim hangisidir?",
        options: { A: "Ateş püskürmek", B: "Etekleri zil çalmak", C: "Burnundan solumak", D: "Göze girmek" },
        correct: "A"
      },
      {
        q: "Bir sanat eserini veya yazıyı olumlu ve olumsuz tüm yönleriyle değerlendiren öğretici yazı türüne ne ad verilir?",
        options: { A: "Biyografi", B: "Eleştiri (Tenkit)", C: "Deneme", D: "Makale" },
        correct: "B"
      },
      {
        q: "Aşağıdaki sözcüklerden hangisi yapım eki alarak türemiş bir sözcüktür?",
        options: { A: "Kitaplar", B: "Simitçi", C: "Evde", D: "Masadan" },
        correct: "B"
      },
      {
        q: "\"Gözleri pırıl pırıl parlayan çocuk heyecanla konuştu.\" cümlesindeki \"pırıl pırıl\" ikilemesi hangi görevde kullanılmıştır?",
        options: { A: "İsim", B: "Zarf (Belirteç)", C: "Zamir", D: "Edat" },
        correct: "B"
      },
      {
        q: "\"Arkadaşının kalbini kıracak çok ağır sözler söyledi.\" cümlesindeki \"ağır\" sözcüğü hangi anlamda kullanılmıştır?",
        options: { A: "Gerçek Anlam", B: "Mecaz Anlam", C: "Terim Anlam", D: "Somut Anlam" },
        correct: "B"
      },
      {
        q: "Kendini herkesten üstün görmek ve kibirlenmek anlamına gelen deyim hangisidir?",
        options: { A: "Burnu havada olmak", B: "Kulak kabartmak", C: "İçi içine sığmamak", D: "Çantada keklik görmek" },
        correct: "A"
      },
      {
        q: "Cümle içerisinde başka bir kimseden veya yazıdan olduğu gibi aktarılan sözlerin başına ve sonuna hangi noktalama işareti konur?",
        options: { A: "Yay ayraç", B: "Tırnak işareti (\" \")", C: "Noktalı virgül", D: "Köşeli ayraç" },
        correct: "B"
      },
      {
        q: "Aşağıdaki cümlelerin hangisinde bir abartma (mübalağa) sanatı kullanılmıştır?",
        options: { A: "Bir of çeksem karşıki dağlar yıkılır.", B: "Rüzgâr usulca pencereme dokundu.", C: "Kış gelince her taraf beyaza büründü.", D: "Yol boyunca sessizce yürüdük." },
        correct: "A"
      },
      {
        q: "Aşağıdaki cümlelerin hangisinde neden-sonuç (gerekçe) ilişkisi vardır?",
        options: { A: "Yoğun kar yağdığı için köy yolları ulaşıma kapandı.", B: "Ders çalışmak üzere kütüphaneye gitti.", C: "Düzenli spor yaparsan sağlıklı kalırsın.", D: "Akşama doğru hava biraz serinledi." },
        correct: "A"
      },
      {
        q: "Bir düşünceyi inandırıcı kılmak için alanında tanınan yetkili bir kişinin sözlerine doğrudan yer vermeye ne ad verilir?",
        options: { A: "Tanımlama", B: "Karşılaştırma", C: "Tanık Gösterme", D: "Örnekleme" },
        correct: "C"
      },
      {
        q: "Aşağıdaki sözcüklerin hangisinde ünlü düşmesi (hece düşmesi) meydana gelmiştir?",
        options: { A: "Gözlük", B: "Aklı", C: "Çiçekler", D: "Masaya" },
        correct: "B"
      },
      {
        q: "\"Şair, bu şiirinde vatan sevgisini ve bayrak aşkını coşkulu bir dille anlatmıştır.\" cümlesinde şiirin hangi yönü belirtilmiştir?",
        options: { A: "İçeriği (Konusu)", B: "Üslubu (Biçemi)", C: "Kafiye düzeni", D: "Ölçüsü" },
        correct: "A"
      },
      {
        q: "Aşağıdaki cümlelerin hangisinde soru eki olan \"mi/mı\"nın yazımı yanlıştır?",
        options: { A: "Sen de bizimle gelecek misin?", B: "Akşamki maç saat kaçta başlıyor?", C: "Söylediklerimi duydunmu?", D: "Bu güzel haberi ona verdiniz mi?" },
        correct: "C"
      }
    ]
  }
};

// Helper: Get list of categories metadata for Host UI
function getCategoriesList() {
  return Object.values(QUESTION_CATEGORIES).map(cat => ({
    id: cat.id,
    name: cat.name,
    badge: cat.badge,
    description: cat.description,
    questionCount: cat.questions.length
  }));
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
    categories: getCategoriesList()
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

  const defaultCategory = 'siber_guvenlik';

  // Room state stored strictly in RAM (zero overhead, references shared questions array)
  const room = {
    pin,
    hostSocketId: null,
    hostIp: clientIp,
    state: 'LOBBY', // 'LOBBY', 'QUESTION', 'RESULT', 'LEADERBOARD', 'PODIUM'
    selectedCategory: defaultCategory,
    questions: QUESTION_CATEGORIES[defaultCategory].questions,
    currentQuestionIndex: -1,
    questionStartTime: 0,
    questionDuration: 20, // 20 seconds per question
    timerInterval: null,
    remainingSeconds: 20,
    players: new Map(), // socketId -> { id, nickname, score, currentAnswer, answeredAt, ip, lastEarnedPoints }
    createdAt: Date.now()
  };

  rooms.set(pin, room);
  console.log(`[ROOM CREATED] PIN: ${pin} by IP: ${clientIp}, Default Category: ${defaultCategory}`);

  res.json({ success: true, pin, selectedCategory: defaultCategory });
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
  const roomQuestions = room.questions || QUESTION_CATEGORIES[room.selectedCategory]?.questions || QUESTION_CATEGORIES['siber_guvenlik'].questions;
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

    socket.emit('host_connected', {
      pin: room.pin,
      state: room.state,
      categories: getCategoriesList(),
      selectedCategory: room.selectedCategory,
      categoryName: QUESTION_CATEGORIES[room.selectedCategory]?.name || '',
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

  // Host selects question category in lobby
  socket.on('host_select_category', (data) => {
    const pin = sanitizeString(data?.pin, 6);
    const categoryId = sanitizeString(data?.categoryId, 40);
    const room = validateHost(pin);
    if (!room) return;

    if (room.state !== 'LOBBY') {
      socket.emit('error_msg', 'Kategori yalnızca lobi aşamasında değiştirilebilir.');
      return;
    }

    if (!QUESTION_CATEGORIES[categoryId]) {
      socket.emit('error_msg', 'Geçersiz kategori seçildi.');
      return;
    }

    room.selectedCategory = categoryId;
    room.questions = QUESTION_CATEGORIES[categoryId].questions;
    console.log(`[CATEGORY SELECTED] Room PIN: ${pin}, Category: ${categoryId} (${QUESTION_CATEGORIES[categoryId].name})`);

    // Notify Host of updated category
    socket.emit('host_category_updated', {
      selectedCategory: categoryId,
      categoryName: QUESTION_CATEGORIES[categoryId].name,
      questionCount: room.questions.length
    });
  });

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

    const roomQuestions = room.questions || QUESTION_CATEGORIES[room.selectedCategory]?.questions || QUESTION_CATEGORIES['siber_guvenlik'].questions;

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
      totalQuestions: roomQuestions.length,
      categoryName: QUESTION_CATEGORIES[room.selectedCategory]?.name || '',
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

    const roomQuestions = room.questions || QUESTION_CATEGORIES[room.selectedCategory]?.questions || [];

    room.state = 'LEADERBOARD';
    const topPlayers = getLeaderboard(room, 5);

    io.to(room.hostSocketId).emit('host_leaderboard_view', {
      leaderboard: topPlayers,
      questionIndex: room.currentQuestionIndex + 1,
      totalQuestions: roomQuestions.length,
      categoryName: QUESTION_CATEGORIES[room.selectedCategory]?.name || ''
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
