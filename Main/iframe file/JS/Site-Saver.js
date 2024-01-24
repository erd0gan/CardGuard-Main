document.addEventListener('DOMContentLoaded', function () {
  // Sayfa yüklenirken mevcut sayfa ve site kayıtlarını başlat
  let currentPage = 1;
  loadSiteRecords();

  // Sayfa yüklenirken örnek siteleri ekle
  addSampleSites();

  // Geçerli site domainini kaydetme işlevi
  window.saveSite = function () {
    const siteUrl = window.location.href;
    const siteDomain = getDomainFromUrl(siteUrl);

    // Local storage'dan mevcut kayıtları al veya boş bir dizi başlat
    const records = JSON.parse(localStorage.getItem('siteRecords')) || [];

    // Alan adının zaten kaydedilip kaydedilmediğini kontrol etmeden önce ekleyin
    if (!records.some(record => record.domain === siteDomain)) {
      // Yeni site kaydını ekle
      records.push({ domain: siteDomain });
    }

    // Kayıtları local storage'a kaydet
    localStorage.setItem('siteRecords', JSON.stringify(records));

    // Site kayıtlarını yeniden yükle
    loadSiteRecords();
  };

  // URL'den domaini çıkarmak için işlev
  function getDomainFromUrl(url) {
    const urlObject = new URL(url);
    return urlObject.hostname;
  }

  // Tüm site kayıtlarını silme işlevi
  window.deleteAll = function () {
    // Local storage'dan tüm site kayıtlarını temizle
    localStorage.removeItem('siteRecords');

    // Site kayıtlarını yeniden yükle
    loadSiteRecords();
  };

  // Site kayıtlarını yükleme ve görüntüleme işlevi
  function loadSiteRecords() {
    const siteList = document.getElementById('siteList');
    const records = JSON.parse(localStorage.getItem('siteRecords')) || [];

    // Geçerli sayfaya dayalı olarak başlangıç ​​ve bitiş indeksini hesapla
    const startIndex = (currentPage - 1) * 5;
    const endIndex = startIndex + 5;

    // Geçerli sayfa için site kayıtlarını görüntüle
    const currentPageRecords = records.slice(startIndex, endIndex);
    siteList.innerHTML = '<h3></h3>';
    currentPageRecords.forEach(record => {
      const recordElement = document.createElement('div');
      recordElement.textContent = record.domain;
      siteList.appendChild(recordElement);
    });

    // Geçerli sayfa numarasını görüntüle
    document.getElementById('currentPage').textContent = currentPage;
  }

  // Geçerli sayfayı değiştirme işlevi
  window.changePage = function (delta) {
    currentPage = Math.max(1, currentPage + delta);
    loadSiteRecords();
  };

  // Örnek siteleri eklemek için işlev
  function addSampleSites() {
    const sampleSites = [
      'https://pttavm.com',
      'https://play.google.com',
      'https://tubitak.gov.tr',
      'https://trthaber.com',
      'https://turkiye.gov.tr'
    ];

    const records = JSON.parse(localStorage.getItem('siteRecords')) || [];

    // Örnek siteleri zaten kaydedilmediyse ekleyin
    sampleSites.forEach(siteUrl => {
      const siteDomain = getDomainFromUrl(siteUrl);
      if (!records.some(record => record.domain === siteDomain)) {
        records.push({ domain: siteDomain });
      }
    });

    // Kayıtları local storage'a kaydet
    localStorage.setItem('siteRecords', JSON.stringify(records));

    // Site kayıtlarını yeniden yükle
    loadSiteRecords();
  }
});
