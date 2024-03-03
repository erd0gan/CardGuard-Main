// Sayfanın karanlık modunu açıp kapatmak için anahtar değiştiricinin değişiklik olayını dinleme
const checkbox = document.getElementById("checkbox");
checkbox.addEventListener("change", () => {
  document.body.classList.toggle("dark");
});

// Sayfanın tamamen yüklenmesini bekleyerek işlemleri gerçekleştirme
document.addEventListener('DOMContentLoaded', function () {
  // HTML'de bulunan anahtar değiştirici ve body elementini seçme
  const checkbox = document.getElementById('checkbox');
  const body = document.body;

  // Kullanıcının tercihine bağlı olarak temayı ayarlayan fonksiyon
  function setTheme(theme) {
    // 'dark' teması seçiliyse body'ye 'dark' sınıfını ekler, aksi takdirde kaldırır
    body.classList.toggle('dark', theme === 'dark');
    // Anahtar değiştirici durumunu günceller
    checkbox.checked = theme === 'dark';
  }

  // Kullanıcının kaydedilmiş bir tercihi var mı diye kontrol etme
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme) {
    // Kaydedilmiş tercihe göre temayı ayarlama
    setTheme(savedTheme);
  }

  // Anahtar değiştirici üzerinde değişiklik olayını dinleme
  checkbox.addEventListener('change', function () {
    // Anahtar değiştirici durumuna göre temayı açıp kapatma
    const theme = checkbox.checked ? 'dark' : 'light';
    setTheme(theme);

    // Kullanıcının tercihini yerel depolamaya kaydetme
    localStorage.setItem('theme', theme);
  });
});

document.getElementById('language-select').addEventListener('change', function() {
  changeLanguage(this.value);
});
