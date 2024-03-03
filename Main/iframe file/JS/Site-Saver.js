
function getActiveTabUrl(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      var activeTab = tabs[0];
      var tabUrl = activeTab.url;
      callback(tabUrl);
  });
}

document.addEventListener('DOMContentLoaded', function () {
  // Sayfa yüklenirken mevcut sayfa ve site kayıtlarını başlat
  let currentPage = 1;
  loadSiteRecords();

  // Sayfa yüklenirken örnek siteleri ekle
  addSampleSites();

  // Geçerli site domainini kaydetme işlevi
  window.saveSite = function () {
    getActiveTabUrl(function(tabUrl) {
      const siteDomain = getDomainFromUrl(tabUrl);
      console.log(siteDomain)
      console.log('Current Site: ' + siteDomain)

      const urlParams = new URLSearchParams(window.location.search);
      const tabParam = urlParams.get('tab');
      console.log('tabParam: ' + tabParam)
      // Local storage'dan mevcut kayıtları al veya boş bir dizi başlat
      const records = JSON.parse(localStorage.getItem('siteRecords_' + tabParam)) || [];

      // Alan adının zaten kaydedilip kaydedilmediğini kontrol etmeden önce ekleyin
      if (!records.some(record => record.domain === siteDomain)) {
        // Yeni site kaydını ekle
        records.push({ domain: siteDomain });
      }

      // Kayıtları local storage'a kaydet
      localStorage.setItem('siteRecords_' + tabParam, JSON.stringify(records));

      // Site kayıtlarını yeniden yükle
      loadSiteRecords();
})};

  // URL'den domaini çıkarmak için işlev
  function getDomainFromUrl(url) {
    const urlObject = new URL(url);
    console.log(urlObject)
    return urlObject.hostname;
  }

  // Tüm site kayıtlarını silme işlevi
  window.deleteAll = function () {
    const urlParams = new URLSearchParams(window.location.search);
    const tabParam = urlParams.get('tab');
    // Local storage'dan tüm site kayıtlarını temizle
    localStorage.removeItem('siteRecords_' + tabParam);

    // Site kayıtlarını yeniden yükle
    loadSiteRecords();
  };

  // Site kayıtlarını yükleme ve görüntüleme işlevi
  function loadSiteRecords() {
    const urlParams = new URLSearchParams(window.location.search);
    const tabParam = urlParams.get('tab');

    const siteList = document.getElementById('siteList');
    const records = JSON.parse(localStorage.getItem('siteRecords_' + tabParam)) || [];

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
    // const sampleSites = [
    //   'https://google.com',
    //   'https://pttavm.com',
    //   'https://tubitak.gov.tr',
    //   'https://trthaber.com',
    //   'https://turkiye.gov.tr',
    //   'https://web.whatsapp.com',
    // ];

    const urlParams = new URLSearchParams(window.location.search);
    const tabParam = urlParams.get('tab');
    const records = JSON.parse(localStorage.getItem('siteRecords_' + tabParam)) || [];

    // Örnek siteleri zaten kaydedilmediyse ekleyin
    // sampleSites.forEach(siteUrl => {
    //   const siteDomain = getDomainFromUrl(siteUrl);
    //   if (!records.some(record => record.domain === siteDomain)) {
    //     records.push({ domain: siteDomain });
    //   }
    // });

    // Kayıtları local storage'a kaydet
    localStorage.setItem('siteRecords_' + tabParam, JSON.stringify(records));

    // Site kayıtlarını yeniden yükle
    loadSiteRecords();
  }
});

document.getElementById('saveButton').addEventListener('click', function() {
  saveSite();
});
document.getElementById('deleteAll').addEventListener('click', function() {
  deleteAll();
});

document.getElementById('previousButton').addEventListener('click', function() {
  changePage(-1);
});

document.getElementById('nextButton').addEventListener('click', function() {
  changePage(1);
});
