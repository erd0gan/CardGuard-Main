// Tüm sekme bağlantılarını ve sekme içeriklerini seçme
const allLinks = document.querySelectorAll(".tabs a");
const allTabs = document.querySelectorAll(".tab-content");

// Her bir sekme bağlantısı için tıklama olayını dinleme
allLinks.forEach((elem) => {
  elem.addEventListener('click', function (event) {
    // Prevent the default behavior of the anchor tag
    event.preventDefault();
    
    const linkId = elem.id;
    const hrefLinkClick = elem.href;

    // Tüm bağlantıları kontrol et
    allLinks.forEach((link) => {
      if (link.href == hrefLinkClick) {
        link.classList.add("active");
      } else {
        link.classList.remove('active');
      }
    });

    // Tüm sekme içeriklerini kontrol et
    allTabs.forEach((tab) => {
      if (tab.id.includes(linkId)) {
        tab.classList.add("tab-content--active");
        // Sekme için içerik oluştur
        generateTabItems(elem, tab);
      } else {
        tab.classList.remove('tab-content--active');
      }
    });
  });
});

// Sekme içeriğini oluşturmak için fonksiyon
const generateTabItems = (elem, tabContent) => {
  const filterName = elem.name;

  // Filtre değişkeninin tanımlı olup olmadığını kontrol et
  if (typeof filter !== 'undefined' && filter[filterName]) {
    const filterFunction = filter[filterName];
    const mappedRecords = tabRecords.filter(filterFunction);
    tabContent.innerHTML = mappedRecords.join('');
  } else {
    console.error("Filter function is not defined.");
  }
};

// Sayfa yüklendiğinde doğru seçimi ele alma
const currentHash = window.location.hash;
let activeLink = document.querySelector('.tabs a');

if (currentHash) {
  const visibleHash = document.getElementById(currentHash.substring(1)); // '#' karakterini kaldır

  if (visibleHash) {
    activeLink = visibleHash;
  }
}

// activeLink varsa devam etmeden önce kontrol etme
if (activeLink) {
  const activeTab = document.querySelector(`#${activeLink.id}-content`);

  activeLink.classList.add('active');
  activeTab.classList.add('tab-content--active');

  generateTabItems(activeLink, activeTab);
}

document.addEventListener('DOMContentLoaded', function () {
  // Sayfanın başlangıcını başlat ve site kayıtlarını yükle
  let currentPage = 1;
  loadSiteRecords();

  // Geçerli site URL'sini kaydetme fonksiyonu
  window.saveSite = function () {
    const siteUrl = window.location.href;
    const records = JSON.parse(localStorage.getItem('siteRecords')) || [];
    records.push({ url: siteUrl });
    localStorage.setItem('siteRecords', JSON.stringify(records));
    loadSiteRecords();
  };

  // Tüm site kayıtlarını silme fonksiyonu
  window.deleteAll = function () {
    localStorage.removeItem('siteRecords');
    loadSiteRecords();
  };

  // Site kayıtlarını yükleme ve görüntüleme fonksiyonu
  function loadSiteRecords() {
    const siteList = document.getElementById('siteList');
    const records = JSON.parse(localStorage.getItem('siteRecords')) || [];
    const currentPage = 1;
    const startIndex = (currentPage - 1) * 5;
    const endIndex = startIndex + 5;

    // siteList.innerHTML = '<h1>Site Records</h1>';
    const currentPageRecords = records.slice(startIndex, endIndex);
    currentPageRecords.forEach((record) => {
      const recordElement = document.createElement('div');
      recordElement.textContent = record.url;
      siteList.appendChild(recordElement);
    });

    document.getElementById('currentPage').textContent = currentPage;
  }

  // Geçerli sayfayı değiştirme fonksiyonu
  window.changePage = function (delta) {
    const currentPage = Math.max(1, currentPage + delta);
    loadSiteRecords();
  };
});