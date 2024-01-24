# CardGuard: Online Alışverişlerde Yüksek Güvenlik - Kart Şifreleme ve Yapay Zekâlı Site Kontrolü
CardGuard, TÜBİTAK 2204-A Lise Öğrencileri Araştırma Projeleri Yarışması için geliştirilmiş bir eklentidir. Bu eklenti kredi kartının şifrelenmiş bir şekilde kaydedilmesi ve gezinilen siteleri tarayarak "Güvenli", "Şüpheli", "Zararlı" olmak üzere 3 kısımda inceler.

## Kurulum

Uzantıyı yüklemek için aşağıdaki adımları izleyiniz:
1. Bu depoyu yerel makinenize klonlayın.
2. Chrome'u açın ve chrome://extensions adresine gidin.
3. Sağ üst köşedeki anahtarı değiştirerek "Geliştirici modunu" açın.
4. "Paketten çıkarılmış olarak yükle "ye tıklayın ve depoyu klonladığınız klasörü seçin.
5. Uzantı artık yüklenmiş ve araç çubuğunuzda görünür olmalıdır.
6. "requirements.txt" dosyası içinde yer alan modülleri kurunuz.
7. Programın çalışması için geçici server olarak CardGuard-Main içerisinde bulunan "Malicious Site Detecter.py" dosyasını başlatmalısınız.
8. "Malicious Site Detecter.py" programı başladıktan sonra eklentiyi kullanabilirsiniz.


## Kullanım

Uzantı yüklendikten sonra aşağıdaki özellikleri kullanabilirsiniz:

## Kredi Kartını Kaydetme

Kartlarım sayfasına girdikten sonra "Kart Ekle" butonuna bastıktan bir şifre belirledikten sonra kart bilgilerinizi kayıt edin.
Eklediğiniz kart AES şifrelemesi ile bir blockchain oluşturulacaktır ve bu şifrelenmiş veri kendi bilgisayarınıza kaydedilecektir.

## Site Kontrolü

Gezdiğiniz siteleri büyük veri tabanları bulunan sitelerden gelen site hakkındaki bilgiler yapay zekâ alanında son teknolojilerden biri olan Generative AI teknolojisiyle beraber taranmaktadır.
Taranan bu veriler en sonunda Güvenli, Şüpheli, Zararlı olmak üzere 3 farklı sonuç verir.
Bu alınan sonuca sitenin Şüpheli veya Zararlı ise kullanıcı uyarılır.

## Çoklu Dil Desteği

Ayarlar sayfasına giderek Türkçe veya İngilizce olarak uzantının dilini değiştirebilisiniz.

## Açık/ Koyu Tema

Ayarlar sayfasında bulunan tema ayarıyla uzantının temasını değiştirebilirsiniz.

## Yapılacaklar Listesi:

-
-
-


## License

