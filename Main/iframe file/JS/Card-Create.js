new Vue({
  el: "#app",
  data() {
    return {
      // Kredi kartı formu için veri alanları
      currentCardBackground: Math.floor(Math.random() * 25 + 1), // Sadece eğlence amaçlı :D
      cardName: "",
      cardNumber: "",
      cardMonth: "",
      cardYear: "",
      cardCvv: "",
      keyInput: "",
      minCardYear: new Date().getFullYear(),
      amexCardMask: "#### ###### #####",
      otherCardMask: "#### #### #### ####",
      cardNumberTemp: "",
      isCardFlipped: false,
      focusElementStyle: null,
      isInputFocused: false,
      password: "",
      passwordVisible: false,
      cardNumber: "",
      formattedCardNumber: "",
    };
  },
  mounted() {
    // Sayfa yüklendiğinde kredi kartı numarası alanına odaklanma
    this.cardNumberTemp = this.otherCardMask;
    document.getElementById("cardNumber").focus();
  },
  computed: {
    // Kredi kartı tipini belirleyen ve maskeyi oluşturan hesaplanmış özellikler
    getCardType() {
      let number = this.cardNumber;
      let re = new RegExp("^4");
      if (number.match(re) != null) return "visa";

      re = new RegExp("^(34|37)");
      if (number.match(re) != null) return "amex";

      re = new RegExp("^5[1-5]");
      if (number.match(re) != null) return "mastercard";

      re = new RegExp("^6011");
      if (number.match(re) != null) return "discover";

      re = new RegExp("^9792");
      if (number.match(re) != null) return "troy";

      return "visa"; // Varsayılan tip
    },
    generateCardNumberMask() {
      // Kredi kartı tipine göre maske oluşturan hesaplanmış özellik
      return this.getCardType === "amex" ? this.amexCardMask : this.otherCardMask;
    },
    minCardMonth() {
      // Minimum kart ayını belirleyen hesaplanmış özellik
      if (this.cardYear === this.minCardYear) return new Date().getMonth() + 1;
      return 1;
    },
  },
  watch: {
    // Kart yılı izleyen bir watcher
    cardYear() {
      // Eğer kart ayı, minimum kart ayından küçükse kart ayını temizle
      if (this.cardMonth < this.minCardMonth) {
        this.cardMonth = "";
      }
    },
  },
  methods: {
    // Kartı çeviren bir metot
    flipCard(status) {
      this.isCardFlipped = status;
    },
    // Giriş alanına odaklanmayı ele alan bir metot
    focusInput(e) {
      this.isInputFocused = true;
      let targetRef = e.target.dataset.ref;
      let target = this.$refs[targetRef];
    
      if (target && target.offsetParent) {
        // Check if the target and its parent are visible
        this.focusElementStyle = {
          width: `${target.offsetWidth}px`,
          height: `${target.offsetHeight}px`,
          transform: `translateX(${target.offsetLeft}px) translateY(${target.offsetTop}px)`,
        };
      }
    },
    
    
    // Giriş alanından odak çıkarma işlemini ele alan bir metot
    blurInput() {
      let vm = this;
      setTimeout(() => {
        if (!vm.isInputFocused) {
          vm.focusElementStyle = null;
        }
      }, 300);
      vm.isInputFocused = false;
    },
    togglePasswordVisibility() {
      this.passwordVisible = !this.passwordVisible;
      // Şifrenin sansürünü kaldırın
      if (this.passwordVisible) {
        
        this.keyInput = this.password;
      } else {
        this.keyInput = this.password.replace(/./g, "*");
      }
      if (this.showPassword) {
        eyeIcon.src = "../../images/eye-off.svg";
      } else {
        eyeIcon.src = "../../images/eye.svg";
      }
    },
  },
});