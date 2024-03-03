
const allLinks = document.querySelectorAll(".tabs a");
const allTabs = document.querySelectorAll(".tab-content")

allLinks.forEach((elem) => {
  elem.addEventListener('click', function() {
    const linkId = elem.id;
    const hrefLinkClick = elem.href;

    allLinks.forEach((link) => {
      if (link.href == hrefLinkClick){
        link.classList.add("active");
      } else {
        link.classList.remove('active');
      }
    });

    allTabs.forEach((tab) => {
      if (tab.id.includes(linkId)) {
        tab.classList.add("tab-content--active");
        // generate content for tab
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

//? mocked for example
const tabRecords = [
  {
    type: 'safe',
  },
  {
    type: 'suspicious',
  },
  {
    type: 'malicious',
  }
];

//? predefined filter functions
const filter = {
  ['safe']: (record) => record.type === 'safe',
  ['suspicious']: (record) => record.type === 'suspicious',
  ['malicious']: (record) => record.type === 'malicious',
}

const generateTabItems = (elem, tabContent) => {
  const filterName = elem.id; // elem.id'yi kullanın
  const filterFunction = filter[filterName];
  
  const iframeURL = `../iframe file/HTML/Site-Saver.html?tab=${filterName}`;
  const sanitizedIframeURL = DOMPurify.sanitize(iframeURL);
  console.log(iframeURL)
  tabContent.innerHTML = `
    <iframe style="position: absolute; left:10px; overflow: hidden;" src="${sanitizedIframeURL}" width="400" height="410" frameborder="0"></iframe>
  `;
}


//? handle proper selection for initial load
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

activeLink.classList.toggle('active');
activeTab.classList.toggle('tab-content--active');

generateTabItems(activeLink, activeTab);

