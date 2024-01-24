var storedLanguage = localStorage.getItem('selectedLanguage');
if (storedLanguage) {
  changeLanguage(storedLanguage);
}

// Dil değişim fonksiyonu
function changeLanguage(lang) {
  // Dil çevirisi objesi
  var langText = {
    'tr': {
      'cardtab1': 'Banka Kartları',
      'cardtab2': 'Kredi Kartları',
      'cardtab3': 'Sanal Kartlar',
      'guardTitle': 'CardGuard',
      'activateGuardText': 'Site Taranıyor.',
      'reportText': 'Herhangi bir tanınmayan veya yetkilendirilmemiş ',
      'reportText1': 'işlemi bildirin.',
      'cardNumber': 'Kart Numarası',
      'cardHolder': 'Kart Sahibi',
      'expiryDate': 'Son Kullanım',
      'showNumber': 'Tüm Numaraları Göster',
      'addCard': 'Kart Ekle',
      'passwordLabel': 'Şifre',
      'getCardDetails': 'Kart Bilgilerini Getir',
      'sitesTitle': 'Siteler',
      'sitetab1Text': 'Güvenli',
      'sitetab2Text': 'Şüpheli',
      'sitetab3Text': 'Zararlı',
      'previousText': 'Önceki',
      'nextText': 'Sonraki',
      'saveSiteText': 'Mevcut Sitesini Kaydet',
      'deleteAllText': 'Tümünü Sil',
      'totalAddedCardText': 'Toplam Eklenen Kart',
      'reliabilityRateText': 'Ziyaret Ettiğiniz Sitelerin Güvenilirlik Oranı',
      'totalSitesText': 'Alışveriş Yaptığınız Toplam Site Sayısı',
      'protectedDaysText': 'Kaç Gündür Korunduğunuz',
      'moreInfoText1': 'Daha Fazla Bilgi',
      'moreInfoText2': 'Daha Fazla Bilgi',
      'moreInfoText3': 'Daha Fazla Bilgi',
      'moreInfoText4': 'Daha Fazla Bilgi',
      'lightDarkMode': 'Light/Dark Mode',
      'faqHeading': 'Açık/Koyu Mod',
      'faqText': 'SSS',
      'faqContent': 'Sıkça Sorulan Sorular',
      'langParam': 'Dil seçiniz',
      'changePassword': 'Şifre Değiştir'

      
    },
    'en': {
      'cardtab1': 'Salary Cards',
      'cardtab2': 'Credit Cards',
      'cardtab3': 'Virtual Cards',
      'guardTitle': 'CardGuard',
      'activateGuardText': 'Site Scanning.',
      'reportText': 'Report any unrecognized or unauthorized transactions.',
      'reportText1': 'on your credit card statement immediately.',
      'cardNumber': 'Card Number',
      'cardHolder': 'Card Holder',
      'expiryDate': 'Expiry Date',
      'showNumber': 'Show Full Numbers',
      'addCard': 'Add Card',
      'passwordLabel': 'Password',
      'getCardDetails': 'Get Card Details',
      'sitesTitle': 'Sites',
      'sitetab1Text': 'Safe',
      'sitetab2Text': 'Suspicious',
      'sitetab3Text': 'Malicious',
      'previousText': 'Previous',
      'nextText': 'Next',
      'saveSiteText': 'Save Current Site',
      'deleteAllText': 'Delete All',
      'totalAddedCardText': 'Total Added Card',
      'reliabilityRateText': 'Reliability Rate of the Sites You Visit',
      'totalSitesText': 'Total Number of Sites You Shop From',
      'protectedDaysText': 'How Many Days Have You Been Protected',
      'moreInfoText1': 'More Info',
      'moreInfoText2': 'More Info',
      'moreInfoText3': 'More Info',
      'moreInfoText4': 'More Info',
      'faqHeading': 'Light/Dark Mode',
      'faqText': 'FAQ',
      'faqContent': 'Frequency Asked Questions',
      'langParam': 'Select Language',
      'changePassword': 'Change Password'
    }
  };

  // Dil çevirisini uygula
  for (var key in langText[lang]) {
    if (langText[lang].hasOwnProperty(key)) {
      var element = document.getElementById(key);
      if (element) {
        element.textContent = langText[lang][key];
      }
    }
  }
}