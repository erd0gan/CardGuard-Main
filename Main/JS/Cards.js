// Tüm bağlantıları ve sekmeleri seçme
const allLinks = document.querySelectorAll(".tabs a");
const allTabs = document.querySelectorAll(".tab-content");

// Her bir bağlantı için click olayını dinleme
allLinks.forEach((elem) => {
  elem.addEventListener('click', function() {
    // Tıklanan bağlantının id'sini ve href'ini alma
    const linkId = elem.id;
    const hrefLinkClick = elem.href;

    // Tüm bağlantıları kontrol etme
    allLinks.forEach((link) => {
      // Tıklanan bağlantının href'ine göre 'active' sınıfını ekleyip kaldırma
      if (link.href == hrefLinkClick){
        link.classList.add("active");
      } else {
        link.classList.remove('active');
      }
    });

    // Tüm sekmeleri kontrol etme
    allTabs.forEach((tab) => {
      // Tıklanan bağlantının id'si içeriyorsa 'tab-content--active' sınıfını ekleyip kaldırma
      if (tab.id.includes(linkId)) {
        tab.classList.add("tab-content--active");
        // Sekme için içerik oluşturma
        generateTabItems(
          elem,
          tab
        );    
      } else {
        tab.classList.remove('tab-content--active');
      }
    });
  });
});

// İlk yükleme için uygun seçimi işleme alma
const currentHash = window.location.hash;

let activeLink = document.querySelector(`.tabs a`);

if (currentHash) {
  const visibleHash = document.getElementById(
    `${currentHash}`
  );

  if (visibleHash) {
    activeLink = visibleHash;
  }
}

const activeTab = document.querySelector(
  `#${activeLink.id}-content`
);

// Başlangıçta seçilen bağlantıya ve sekme içeriğine 'active' ve 'tab-content--active' sınıflarını ekleyip kaldırma
activeLink.classList.toggle('active');
activeTab.classList.toggle('tab-content--active');
