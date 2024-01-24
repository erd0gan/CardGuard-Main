// Resim ve metin değişiklikleri için bir fonksiyon
function changeImage(currentUrl) {
    // Resim ve metin elementlerini alma
    var imageElement = document.getElementById('guardImage');
    var activationText = document.querySelector('.activation-text');

    if (imageElement && activationText) {
        var currentImage = imageElement.src;
    
        // URL yapısını kullanarak protokolü alma
        var protocol = new URL(currentUrl).protocol;
    
        // // HTTPS protokolü için işlemler
        // if (protocol === 'https:') {
        //     if (currentImage.endsWith('inactive-log.webp')) {
        //         imageElement.src = '../images/safe-log.webp';
        //         activationText.textContent = "Ziyaret ettiğiniz site güvenli!";
        //     } else if (currentImage.endsWith('safe-log.webp')) {
        //         imageElement.src = '../images/inactive-log.webp';
        //         activationText.textContent = "Korumayı etkinleştirmek için kalkanı tıklayın.";
        //     }
        // } else {
        //     // HTTP protokolü için farklı bir logo ayarlama
        //     if (currentImage.endsWith('inactive-log.webp')) {
        //         imageElement.src = '../images/malicious-log.webp';
        //         activationText.textContent = "Bu site tehlikeli olabilir.";
        //     } else if (currentImage.endsWith('malicious-log.webp')) {
        //         imageElement.src = '../images/inactive-log.webp';
        //         activationText.textContent = "Korumayı etkinleştirmek için kalkanı tıklayın.";
        //     }
        // }
    
        // Aktivasyon metnine 'typewriter' sınıfını ekleme
        activationText.classList.add('typewriter');
    
        // Animasyon tamamlandıktan sonra 'typewriter' sınıfını kaldırma
        setTimeout(function () {
            activationText.classList.remove('typewriter');
        }, 1000);
    } else {
        console.error("Image element or activation text not found.");
    }
}


// Geçerli alan adını güncelleme fonksiyonu
function updateCurrentDomain(currentUrl) {
    // Protokol ve alan adını alma
    var urlObject = new URL(currentUrl);
    var protocol = urlObject.protocol;
    var domain = urlObject.hostname;
  
    // Uyarı metni elementini seçme ve font stilini ayarlama
    var warningText = document.querySelector('.activation-text');
    warningText.style.fontFamily = 'Open Sans, sans-serif';
  
    // Kombine protokol ve alan adını belirtilen elementte gösterme
    var currentDomainElement = document.getElementById('currentDomain');
    currentDomainElement.textContent = domain;
    currentDomainElement.style.color = (protocol === 'http:') ? 'red' : 'green';
  }
  

// İstek gönderme fonksiyonu
function sendRequests(targetUrl) {
  var url = 'http://127.0.0.1:5000';

  var postData = {'site': targetUrl};
  var headers = {'Content-Type': 'application/json'};

  var xhr = new XMLHttpRequest();
  xhr.open('POST', url, true);
  xhr.setRequestHeader('Content-Type', 'application/json');

  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var response = JSON.parse(xhr.responseText);
      var resultData = response.ai_data_result;

      // Algılama sonuçları için düzenli ifadeler
      var securityPattern = /security is ([^.]+)/;
      var reliabilityPattern = /(\d\d|\d)%/;

      // Düzenli ifadelerle eşleşmeyi kontrol etme
      var securityMatch = resultData.match(securityPattern);
      var reliabilityMatch = resultData.match(reliabilityPattern);

      // Eğer eşleşme varsa, mesajı oluşturma
      if (securityMatch && reliabilityMatch) {
        var securityType = securityMatch[1];
        var reliabilityRate = reliabilityMatch[1];

        var activationText = document.querySelector('.activation-text');
        activationText.textContent = "Ziyaret ettiğiniz site " + securityType + " ve güvenilirlik oranı " + reliabilityRate + "%.";

        // Logo değiştirme işlemi
        var imageElement = document.getElementById('guardImage');
        if (securityType.toLowerCase() === 'malicious') {
          imageElement.src = '../images/malicious-log.webp';
        } else if (securityType.toLowerCase() === 'safe') {
          imageElement.src = '../images/safe-log.webp';
        } else if (securityType.toLowerCase() === 'suspicious') {
          imageElement.src = '../images/suspicious-log.webp';
        } else {
          imageElement.src = '../images/inactive-log.webp';
        }

        // Stil ve animasyon ekleme işlemleri burada devam edebilir
        activationText.classList.add('typewriter');

        setTimeout(function () {
          activationText.classList.remove('typewriter');
        }, 1000);
      }

      // Domain sonuçlarıyla ilgili işlemler burada devam edebilir
      var domainData = response.ai_domain_result;
    }
  };

  var jsonData = JSON.stringify(postData);
  xhr.send(jsonData);
}


function getActiveTab() {
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
            resolve(tab);
        });
    });
}

 
document.addEventListener("DOMContentLoaded", async () => {
    const tab = await getActiveTab();
    currentUrl = tab.url
    console.log("Current URL: " + currentUrl);
    changeImage(currentUrl);
    updateCurrentDomain(currentUrl);
    sendRequests(currentUrl);
});
