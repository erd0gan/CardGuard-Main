// Canvas elementini al
const ctx = document.getElementById("revenues");

// Chart.js ayarlarını yapılandır
Chart.defaults.color = "#FFF";
Chart.defaults.font.family = "Open Sans";

// Yeni bir çubuk grafik oluştur ve canvas elementine bağla
new Chart(ctx, {
  type: "bar", // Grafik tipi: çubuk grafik
  data: {
    labels: [
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec",
    ], // X ekseni etiketleri: aylar
    datasets: [
      {
        label: "Sites Count", // Veri setinin etiketi
        data: [
          5, 7, 12, 16, 19, 28, 35, 40, 42, 45, 50, 60,
        ], // Y eksenindeki veriler: her ay için site sayısı
        backgroundColor: "#F4BD50", // Çubukların arkaplan rengi
        borderRadius: 6, // Çubuk köşe yuvarlama
        borderSkipped: false, // Çubukların kenarlarındaki boşluk
      },
    ],
  },
  options: {
    responsive: true, // Grafik boyutunu tarayıcı boyutuna göre ayarla
    maintainAspectRatio: false, // En boy oranını koruma
    plugins: {
      legend: {
        display: false, // Açıklama penceresini gizle
      },
      title: {
        display: true,
        text: "2023 Yılında Korunduğunuz Site Sayısı", // Grafik başlığı
        padding: {
          bottom: 16,
        },
        font: {
          size: 16,
          weight: "normal",
        },
      },
      tooltip: {
        backgroundColor: "#27292D", // İpucu arkaplan rengi
      },
    },
    scales: {
      x: {
        border: {
          dash: [2, 4], // X ekseni için çizgi tipi
        },
        grid: {
          color: "#27292D", // X ekseni ızgarası rengi
        },
        title: {
          text: "2023", // X ekseni başlığı
        },
      },
      y: {
        grid: {
          color: "#27292D", // Y ekseni ızgarası rengi
        },
        border: {
          dash: [2, 4], // Y ekseni için çizgi tipi
        },
        beginAtZero: true, // Y eksenini sıfırdan başlat
        title: {
          display: true,
          text: "Sites Count", // Y ekseni başlığı
        },
      },
    },
  },
});
