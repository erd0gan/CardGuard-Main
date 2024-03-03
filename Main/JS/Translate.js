var storedLanguage = localStorage.getItem('selectedLanguage');
console.log('Selected Language: ' + storedLanguage)
if (storedLanguage) {
  changeLanguage(storedLanguage);
}

// Dil değişim fonksiyonu
function changeLanguage(lang) {
  // Dil çevirisi objesi
  var langText = {
    'tr': {
      'salary': 'Banka Kartları',
      'credit': 'Kredi Kartları',
      'virtual': 'Sanal Kartlar',
      'guardTitle': 'CardGuard',
      'activateGuardText': 'Site Taranıyor.',
      'reportText': 'Herhangi bir tanınmayan veya <br>yetkilendirilmemiş işlemi bildirin.',
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
      'changePassword': 'Şifre Değiştir',
      'title1': 'Kartların güvenliğini nasıl sağlıyorsunuz?',
      'content1': 'AES şifreleme tekniği sayesinde, kartlarınıza tanımlanmış olan benzersiz bir anahtar, kartlarınızı şifreler ve sizin şifreniz olmadan kırılması neredeyse imkansızdır!',
      'title2': 'Zararlı siteleri nasıl tespit ediyorsunuz?',
      'content2': 'Zararlı siteleri, eğittiğimiz bir yapay zeka tarafından tespit edilir. Yapay zekamız, belirli kriterlere göre güvenli ve zararlı sitelere maruz kaldığı için bunlar arasındaki farkı kolayca anlayabilir.',
      'title3': 'Uzantının verilerimize erişimi var mı?',
      'content3': 'Hayır, uzantı girdiğiniz bilgileri yalnızca sizin erişebileceğiniz cihazınızın yerel depolama alanına kaydeder, bu nedenle bilgileriniz internet akışında paylaşılmaz.',
      'title4': 'Kredi kartımı tam koruma sağlar mı?',
      'content4': 'Eklemeyi kullandığınızda kredi kartınızın daha güvende olacağını söyleyebiliriz, ancak kimse tam koruma garanti edemez!',
      'title5': 'Verileriniz nereden geliyor?',
      'content5': 'Veriler, antivirüs hizmetleri gibi birçok veri kaynağından gelir ve yapay zekamız bunu işler.',
      'records': 'Website Kayıtları',
      'saveButton': 'Aktif Siteyi Kaydet',
      'deleteAll': 'Tüm Kayıtlı Siteleri Sil',
    },
    'en': {
      'salary': 'Salary Cards',
      'credit': 'Credit Cards',
      'virtual': 'Virtual Cards',
      'guardTitle': 'CardGuard',
      'activateGuardText': 'Site Scanning.',
      'reportText': 'Report any unauthorized transactions on<br> your credit card statementim mediately.',
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
      'changePassword': 'Change Password',
      'title1': 'How do you ensure the security of the cards?',
      'content1': 'Thanks to the AES encryption technique, you have a unique key defined to your internal password that encrypts your cards and is almost impossible to crack without your password!',
      'title2': 'How do you detect malicious sites?',
      'content2': 'Malicious sites are detected by an artificial intelligence that we have trained. Our AI has been exposed to safe and malicious sites on certain criteria so that it can easily tell the difference between them.',
      'title3': 'Does the extension have access to any of our data?',
      'content3': 'No, the extension saves the information you enter to local storage on your device that only you can access, so none of your information is shared on the internet stream.',
      'title4': 'Does it provide full protection of my credit card?',
      'content4': 'We can say that your credit card will be more secure if you use the add-on, but no one can guarantee full protection!',
      'title5': 'Where does your data come from?',
      'content5': 'It comes from multiple data sources, like antivirus services, which are big data sources, and our AI processes it.',
      'records': 'Website Records',
      'saveButton': 'Save Current Site',
      'deleteAll': 'Delete All',
    }
  };

  // Dil çevirisini uygula
  for (var key in langText[lang]) {
    if (langText[lang].hasOwnProperty(key)) {
      var element = document.getElementById(key);
      if (element) {
        element.innerHTML = langText[lang][key];
      }
    }
  }
  localStorage.setItem('selectedLanguage', lang)
}