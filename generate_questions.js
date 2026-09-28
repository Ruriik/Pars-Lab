const fs = require('fs');

const generateQuestions = (subject, topic, diff, count) => {
  const q = [];
  for(let i=1; i<=count; i++) {
    q.push({
      q: `[${diff}] ${subject} - ${topic} (Soru ${i}): Maarif modeli çerçevesinde öğrencinin muhakeme yeteneğini ölçecek örnek soru metni. (Gerçek e-Devlet/MEB bağlantısı yapıldığında bu alan API'den dolacaktır.)`,
      options: { A: 'A Seçeneği', B: 'B Seçeneği', C: 'C Seçeneği', D: 'D Seçeneği' },
      correct: ['A','B','C','D'][Math.floor(Math.random()*4)]
    });
  }
  return q;
};

// Gerçek bir iki soru ekleyelim:
const realTarihQ = [
  {
    q: "Maarif modeline göre; İlk Çağ'da Sümerlerin yazıyı bulması, insanlık tarihi açısından hangi becerinin gelişimine en çok katkı sağlamıştır?",
    options: { A: "Tarımsal üretim artışı", B: "Bilgi birikimi ve aktarımı", C: "Göçebe yaşamın yaygınlaşması", D: "Çok tanrılı dinlerin ortaya çıkması" },
    correct: "B"
  },
  {
    q: "Lidyalıların parayı icat etmesi, değiş-tokuş usulünü bitirmiştir. Bu durumun ticari hayatta yarattığı en büyük dönüşüm nedir?",
    options: { A: "Ticaretin hızlanması ve kolaylaşması", B: "Tarımın terk edilmesi", C: "Şehir devletlerinin yıkılması", D: "Sınıf farklılıklarının tamamen ortadan kalkması" },
    correct: "A"
  }
];

const tarihZorQuestions = generateQuestions('Tarih', 'İlk Çağ', 'Zor', 18);
const tarihZorTest = [...realTarihQ, ...tarihZorQuestions];

const db = {
  grades: {
    '9': {
      name: '9. Sınıf',
      subjects: {
        'tarih': {
          name: 'Tarih',
          icon: 'scroll',
          topics: {
            'ilkcag': {
              name: 'İlk Çağ Uygarlıkları',
              tests: {
                'kolay': { name: 'Kolay (Hatırlama)', questions: generateQuestions('Tarih', 'İlk Çağ', 'Kolay', 20) },
                'orta': { name: 'Orta (Anlama)', questions: generateQuestions('Tarih', 'İlk Çağ', 'Orta', 20) },
                'zor': { name: 'Zor (Maarif Analiz)', questions: tarihZorTest }
              }
            },
            'islam_tarihi': {
              name: 'İslam Tarihi',
              tests: {
                'kolay': { name: 'Kolay Seviye', questions: generateQuestions('Tarih', 'İslam Tarihi', 'Kolay', 20) },
                'orta': { name: 'Orta Seviye', questions: generateQuestions('Tarih', 'İslam Tarihi', 'Orta', 20) },
                'zor': { name: 'Zor (Maarif Analiz)', questions: generateQuestions('Tarih', 'İslam Tarihi', 'Zor', 20) }
              }
            }
          }
        },
        'matematik': {
          name: 'Matematik',
          icon: 'calculator',
          topics: {
            'mantik': {
              name: 'Mantık ve Önermeler',
              tests: {
                'kolay': { name: 'Kolay Seviye', questions: generateQuestions('Matematik', 'Mantık', 'Kolay', 20) },
                'orta': { name: 'Orta Seviye', questions: generateQuestions('Matematik', 'Mantık', 'Orta', 20) },
                'zor': { name: 'Zor (Maarif Analiz)', questions: generateQuestions('Matematik', 'Mantık', 'Zor', 20) }
              }
            },
            'kumeler': {
              name: 'Kümeler',
              tests: {
                'kolay': { name: 'Kolay Seviye', questions: generateQuestions('Matematik', 'Kümeler', 'Kolay', 20) },
                'orta': { name: 'Orta Seviye', questions: generateQuestions('Matematik', 'Kümeler', 'Orta', 20) },
                'zor': { name: 'Zor (Maarif Analiz)', questions: generateQuestions('Matematik', 'Kümeler', 'Zor', 20) }
              }
            }
          }
        },
        'fizik': {
          name: 'Fizik',
          icon: 'atom',
          topics: {
            'fizik_bilimine_giris': {
              name: 'Fizik Bilimine Giriş',
              tests: {
                'kolay': { name: 'Kolay Seviye', questions: generateQuestions('Fizik', 'Giriş', 'Kolay', 20) },
                'orta': { name: 'Orta Seviye', questions: generateQuestions('Fizik', 'Giriş', 'Orta', 20) },
                'zor': { name: 'Zor (Maarif Analiz)', questions: generateQuestions('Fizik', 'Giriş', 'Zor', 20) }
              }
            }
          }
        }
      }
    },
    '10': {
      name: '10. Sınıf',
      subjects: {
        'biyoloji': {
          name: 'Biyoloji',
          icon: 'dna',
          topics: {
            'hucre': {
              name: 'Hücre Bölünmeleri',
              tests: {
                'kolay': { name: 'Kolay', questions: generateQuestions('Biyoloji', 'Hücre', 'Kolay', 20) },
                'orta': { name: 'Orta', questions: generateQuestions('Biyoloji', 'Hücre', 'Orta', 20) },
                'zor': { name: 'Zor', questions: generateQuestions('Biyoloji', 'Hücre', 'Zor', 20) }
              }
            }
          }
        }
      }
    }
  }
};

fs.writeFileSync('questions.json', JSON.stringify(db, null, 2));
console.log('questions.json created successfully.');
