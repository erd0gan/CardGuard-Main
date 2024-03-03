// Vue instance oluşturma

const app = Vue.createApp({
  el: "#app",
  
  data() {
    
    return {
      // Kart verilerini depolamak için boş bir dizi oluşturma
      cards: [],
      activeIndex: 0,
      activeCard: null,
      showPassword: false,
    };
  },
  define: {
    __INTLIFY_JIT_COMPILATION__: true
  },
  methods: {
    // Kartın tipini belirleme fonksiyonu
    getCardType(card) {
      if (card.cardNumber.charAt(0) === "4") {
        return "visa";
      } else if (card.cardNumber.charAt(0) === "5") {
        return "mastercard";
      } else if (card.cardNumber.charAt(0) === "3") {
        return "amex";
      } else if (card.cardNumber.substring(0, 4) === "6011") {
        return "discover";
      } else if (card.cardNumber.substring(0, 4) === "9792") {
        return "troy";
      } else {
        return "mastercard";
      }
    },
    // Kart logosunu belirleme fonksiyonu
    getCardLogo(card) {
      return `../../images/${this.getCardType(card)}.png`;
    },
    // Kartı çevirme fonksiyonu
    flipCard(card, event) {
      if (event.target.classList.contains('card-form__button')) {
        return;
      }

      this.rotateCard(card);
      card.flipped = !card.flipped;
    },

    rotateCard(card) {
      card.rotateY = card.rotateY === 0 ? 180 : 0;
    },

    // Kart numarasını formatlama fonksiyonu
    formatCardNumber(cardNumber) {
      // Kart numarasının ilk 4 ve son 4 hanesini al
      const firstFour = cardNumber.substring(0, 4);
      const lastFour = cardNumber.substring(cardNumber.length - 4);
      return `${firstFour} **** **** ${lastFour}`;
    },
    // Kart numarasını tam gösterme fonksiyonu
    toggleFullNumber(card) {
      card.showFullNumber = !card.showFullNumber;
    },
    
    // Kart eklemesi yapılacak yere yönlendirme fonksiyonu
    cardDetails(selectedCard) {
      this.cards.forEach((card) => {
        card.visible = card.id === selectedCard.id;
        card.flipped = false;
      });
      const urlParams = new URLSearchParams(window.location.search);
      const tabParam = urlParams.get('tab');
      console.log('help')
      console.log(tabParam)
      window.location.href = "../HTML/Card-Create.html?tab=" + tabParam;
    },

    // Sonraki kartı gösterme fonksiyonu
    showNextCard() {
      this.changeActiveCard(1);
    },

    showPreviousCard() {
      this.changeActiveCard(-1);
    },
    changeActiveCard(step) {
      const newIndex = this.activeIndex + step;
      if (newIndex >= 0 && newIndex < this.cards.length) {
        this.activeIndex = newIndex;
        this.activeCard = this.cards[this.activeIndex];
      }
    },
    // Metni panoya kopyalama fonksiyonu
    copyToClipboard(text) {
      const tempInput = document.createElement('input');
      tempInput.value = text;
      document.body.appendChild(tempInput);
      tempInput.select();
      document.execCommand('copy');
      document.body.removeChild(tempInput);

      // Özel bildirim penceresini gösterme
      const popup = document.getElementById('copyPopup');
      popup.classList.add('notification--visible');

      // Pencereyi 2 saniye sonra gizleme (gerektiğinde süreyi ayarlayabilirsiniz)
      setTimeout(() => {
        popup.classList.remove('notification--visible');
      }, 2000);

      event.stopPropagation();
    },
    // Kart detaylarını getirme fonksiyonu
    async getCardDetails() {
      const urlParams = new URLSearchParams(window.location.search);
      const tabParam = urlParams.get('tab');

      console.log(tabParam); // tab parametresini konsola yazdırır

      const blockchainName = `blockchain_${tabParam}`;

      let decryptedBlockchain;
      
      const storedEncryptedBlockchain = localStorage.getItem(blockchainName);
      
      console.log('Stored Name')
      console.log(blockchainName)

      if (storedEncryptedBlockchain) {
        const secretKey = document.getElementById("keyInput").value.trim();

        if (secretKey) {
          console.log("Secret Key:", secretKey);
        } else {
          console.log("Invalid or missing secret key. Please go back to the control page.");
          alert("Invalid or missing secret key. Please go back to the control page.");
          return;
        }

        console.log("secretKey: " + secretKey);
        console.log("1. Side");

        try {
          console.log("storedEncryptedBlockchain: " + storedEncryptedBlockchain);
          decryptedBlockchain = await decryptBlockchain(storedEncryptedBlockchain, secretKey);
          console.log("decryptedBlockchain", decryptedBlockchain);

          if (!decryptedBlockchain) {
            console.log("Invalid secret key. Please refresh the page and try again.");
            alert("Invalid secret key. Please refresh the page and try again.");
            return;
          }
        } catch (error) {
          console.error("Error during decryption:", error);
          alert("An error occurred during decryption. Please check the console for details.");
          return;
        }
      } else {
        console.log("No encrypted blockchain data found. Please go back to the control page.");
        alert("No encrypted blockchain data found. Please go back to the control page.");
        return;
      }

      try {
        const cardList = decodeAndSplitData(decryptedBlockchain);
        this.refreshInfo(cardList);
      } catch (error) {
        console.error("Error while updating card details:", error);
      }
    },

    // Bilgileri güncelleme fonksiyonu
    refreshInfo(cardList) {
      this.cards = cardList;
      this.activeIndex = 0;
      this.activeCard = this.cards[this.activeIndex];
    },

    togglePassword(event) {
      this.showPassword = !this.showPassword;
      // Şifrenin değerini güncelle
      this.password = event.target.value;

      const eyeIcon = document.querySelector(".input__icon");
      if (this.showPassword) {
        eyeIcon.src = "../../images/eye-off.svg";
      } else {
        eyeIcon.src = "../../images/eye.svg";
      }
    },

    handleCardClick(activeCard) {
      this.flipCard(activeCard);
    },
  },
  created() {
    this.cards = [{
      id: 0,
      cardName: "Genesis Card",
      cardNumber: "0000 0000 0000 0000",
      cardMonth: 1,
      cardYear: 2023,
      cardCvv: "000",
      cardType: "genesis",
      flipped: false,
      showFullNumber: false,
      rotateY: 0,
      visible: true,
    }];
    this.activeCard = this.cards[this.activeIndex];
  },
});


// URL'den parametreleri al






app.mount('#app'); // Ensure the app is mounted to the element with #app ID
