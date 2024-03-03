document.charset = "UTF-8";
const urlParams = new URLSearchParams(window.location.search);
const tabParam = urlParams.get('tab');
console.log(tabParam); // tab parametresini konsola yazdırır
const blockchainName = `blockchain_${tabParam}`;
console.log("Active Blockchain: " + blockchainName)

document.querySelector('.card-form__button').addEventListener('click', function() {
    initializeApp();
});

function encryptData() {
    // Önce addToBlockchain fonksiyonunu çağır
    addToBlockchain();

    // Daha sonra blockchain verisini al ve şifrele
    const key_for_hash = document.getElementById("key_input").value;
    console.log("key_for_hash: " + key_for_hash);

    const blockchainData = JSON.stringify(blockchain.chain);
    const key = CryptoJS.MD5(key_for_hash).toString();

    const encryptedData = CryptoJS.AES.encrypt(blockchainData, key, {
        mode: CryptoJS.mode.CFB,
        padding: CryptoJS.pad.Pkcs7,
        iv: CryptoJS.lib.WordArray.random(16),
    });

    console.log("encryptedData: " + encryptedData);

    // Kaydedilen şifrelenmiş veriyi yerel depolamaya ekleyin veya başka bir işlem yapın
    localStorage.setItem(blockchainName, encryptedData.toString());

    // Display output
    document.getElementById("output").innerHTML = "Encrypted data: " + encryptedData;
}

// function decryptData(encryptedDataString) {
//     const key_for_hash = document.getElementById("key_input").value.trim();
//     //const encryptedDataString = document.getElementById("output").innerText.split(": ")[1].trim();

//     // Generate hashed key
//     const key = CryptoJS.MD5(key_for_hash).toString();
//     console.log("key: " + key);

//     // Decrypt data using AES-CFB with PKCS#7 padding
//     const decryptedData = CryptoJS.AES.decrypt(encryptedDataString, key, {
//         mode: CryptoJS.mode.CFB,
//         padding: CryptoJS.pad.Pkcs7,
//     });
//     console.log("decryptedData: " + decryptedData);

//     // Convert decrypted data to string
//     const decryptedString = CryptoJS.enc.Utf8.stringify(decryptedData);
//     console.log("decryptedString: " + decryptedString);

//     // Display output
//     document.getElementById("output").innerHTML = "Decrypted data: " + decryptedString;
// }

function initializeApp() {
    const storedEncryptedBlockchain = localStorage.getItem(blockchainName);
    console.log(blockchainName)
    if (storedEncryptedBlockchain) {
        // Eğer şifrelenmiş blockchain verisi varsa, anahtar girişi istenir
        const secretKey = document.getElementById("keyInput").value.trim()


        // Check if the key is present
        if (secretKey) {
            // Use the key in your application logic
            console.log("Secret Key:", secretKey);
        } else {
            // If the key is not present, handle the situation accordingly
            console.log("Invalid or missing secret key. Please go back to the control page.");
            alert("Invalid or missing secret key. Please go back to the control page.");
        }
        console.log("secretKey: " + secretKey);
        console.log("1. Side");
        if (secretKey) {
            try {
                // Anahtar ile şifrelenmiş blockchain verisi çözülür
                console.log("storedEncryptedBlockchain: " + storedEncryptedBlockchain);
                const decryptedBlockchain = decryptBlockchain(storedEncryptedBlockchain, secretKey);
                console.log("decryptedBlockchain", decryptedBlockchain);

                if (decryptedBlockchain) {
                    const blockchainInstance = new Blockchain(secretKey); // Yeni bir örnek oluşturun
                    blockchainInstance.chain = decryptedBlockchain; // Decrypted blockchain ile güncelleyin
    
                    // Çözülen blockchain üzerine yeni kredi kartı eklenir
                    addCreditCardToBlockchain(blockchainInstance);
                    
                    // Şifrelenmiş veri tekrar kaydedilir
                    saveEncryptedBlockchain(blockchainInstance, secretKey);
                    window.location.href = 'Card-Showcase.html?tab=' + tabParam;
                } else {
                    console.log("Invalid secret key. Please refresh the page and try again.")
                    alert("Invalid secret key. Please refresh the page and try again.");
                }
            } catch (error) {
                console.error("Error during decryption:", error);
                alert("An error occurred during decryption. Please check the console for details.");
            }
        } else {
            console.log("Secret key is required. Please refresh the page and try again.")
            alert("Secret key is required. Please refresh the page and try again.");
        }

    } else {
        const secretKey = document.getElementById("keyInput").value.trim();

        // Check if the key is present
        if (secretKey) {
            // Use the key in your application logic
            console.log("Secret Key:", secretKey);
            const blockchainInstance = new Blockchain(secretKey); // Yeni bir örnek oluşturun

            // Çözülen blockchain üzerine yeni kredi kartı eklenir
            addCreditCardToBlockchain(blockchainInstance);
            
            // Şifrelenmiş veri tekrar kaydedilir
            saveEncryptedBlockchain(blockchainInstance, secretKey);
            window.location.href = 'Card-Showcase.html?tab=' + tabParam;
        } else {
            // If the key is not present, handle the situation accordingly
            console.log("Invalid or missing secret key. Please go back to the control page.")
            alert("Invalid or missing secret key. Please go back to the control page.");
        }
        console.log("secretKey: " + secretKey);
        console.log("2. Side");
        const blockchain = new Blockchain(secretKey);
        
        // Kullanıcının girdiği anahtar ile şifrelenip kaydedilir
        if (secretKey) {
            saveEncryptedBlockchain(blockchain, secretKey);
        } else {
            console.log("Secret key is required. Please refresh the page and try again.")
            alert("Secret key is required. Please refresh the page and try again.");
        }
        }
}
function loadCardDetails() {
    const storedEncryptedBlockchain = localStorage.getItem(blockchainName);
    
    if (storedEncryptedBlockchain) {
        // Eğer şifrelenmiş blockchain verisi varsa, anahtar girişi istenir
        const secretKey = document.getElementById("key_input").value.trim();

        // Check if the key is present
        if (secretKey) {
            // Use the key in your application logic
            console.log("Secret Key:", secretKey);
        } else {
            // If the key is not present, handle the situation accordingly
            console.log("Invalid or missing secret key. Please go back to the control page.")
            alert("Invalid or missing secret key. Please go back to the control page.");
        }
        console.log("secretKey: " + secretKey);
        console.log("1. Side");
        if (secretKey) {
            try {
                // Anahtar ile şifrelenmiş blockchain verisi çözülür
                console.log("storedEncryptedBlockchain: " + storedEncryptedBlockchain);
                const decryptedBlockchain = decryptBlockchain(storedEncryptedBlockchain, secretKey);
                console.log("decryptedBlockchain", decryptedBlockchain);

                if (decryptedBlockchain) {
                    const blockchainInstance = new Blockchain(); // Yeni bir örnek oluşturun
                    blockchainInstance.chain = decryptedBlockchain; // Decrypted blockchain ile güncelleyin
                } else {
                    console.log("Invalid secret key. Please refresh the page and try again.")
                    alert("Invalid secret key. Please refresh the page and try again.");
                }
            } catch (error) {
                console.error("Error during decryption:", error);
                alert("An error occurred during decryption. Please check the console for details.");
            }
        } else {
            console.log("Secret key is required. Please refresh the page and try again.")
            alert("Secret key is required. Please refresh the page and try again.");
        }

    } else {
        const secretKey = document.getElementById("key_input").value.trim();

        // Check if the key is present
        if (secretKey) {
            // Use the key in your application logic
            console.log("Secret Key:", secretKey);
            const blockchainInstance = new Blockchain(); // Yeni bir örnek oluşturun
            saveEncryptedBlockchain(blockchainInstance, secretKey);
        } else {
            // If the key is not present, handle the situation accordingly
            console.log("Invalid or missing secret key. Please go back to the control page.")
            alert("Invalid or missing secret key. Please go back to the control page.");
        }
        console.log("secretKey: " + secretKey);
        console.log("2. Side");
        const blockchain = new Blockchain();
        
        // Kullanıcının girdiği anahtar ile şifrelenip kaydedilir
        if (secretKey) {
            saveEncryptedBlockchain(blockchain, secretKey);
        } else {
            console.log("Secret key is required. Please refresh the page and try again.")
            alert("Secret key is required. Please refresh the page and try again.");
        }
    }
}
// Şifrelenmiş blockchain verisini kaydeden fonksiyon
function saveEncryptedBlockchain(blockchain, secretKey) {
    const blockchainData = JSON.stringify(blockchain.chain);
    const key = CryptoJS.MD5(secretKey).toString();
    
    const encryptedData = CryptoJS.AES.encrypt(blockchainData, key, {
        mode: CryptoJS.mode.CFB,
        padding: CryptoJS.pad.Pkcs7,
        iv: CryptoJS.lib.WordArray.random(16),
    });
    
    // encryptedData'nın bir dize olarak saklandığından emin olun
    localStorage.setItem(blockchainName, encryptedData.toString());
}


function base64encode(str) {
    return btoa(unescape(encodeURIComponent(str)));
}

// Yeni kredi kartı ekleyen fonksiyon
function addCreditCardToBlockchain(blockchain) {
    // Kredi kartı eklemeye yönelik gerekli işlemler burada yapılır
    // Örnek olarak:
    const creditCard = document.getElementById("cardNumber").value;
    const cardName = document.getElementById("cardName").value;
    const expiryMonth = document.getElementById("cardMonth").value;
    console.log("expiryMonth" + expiryMonth);
    const expiryYear = document.getElementById("cardYear").value;
    console.log("expiryYear" + expiryYear);
    const cvv = document.getElementById("cardCvv").value;
    console.log("cvv" + cvv);

    // Use encodeURIComponent for consistent encoding
    const data = `${encodeURIComponent(creditCard)}|${encodeURIComponent(cardName)}|${expiryMonth}|${expiryYear}|${cvv}`;
    console.log("Adding Credit Card: " + data);
    const utf8Data = unescape(encodeURIComponent(data)); // UTF-8'e dönüştür

    const encryptedData = base64encode(utf8Data); // base64 ile kodla
    console.log("Encrypting Credit Card with Base64: " + encryptedData);
    console.log(blockchain);
    blockchain.addBlock(new Block(
        blockchain.getLatestBlock().index + 1,
        blockchain.getLatestBlock().hash,
        encryptedData,
        Math.floor(new Date().getTime() / 1000),
        0
    ));
}

// Program başlangıcında initializeApp fonksiyonu çağrılır
function addToBlockchain() {
    const creditCard = document.getElementById("creditCard").value;
    const expiryMonth = document.getElementById("expiryMonth").value;
    const expiryYear = document.getElementById("expiryYear").value;
    const cvv = document.getElementById("cvv").value;

    const data = `${creditCard}|${expiryMonth}|${expiryYear}|${cvv}`;
    const encryptedData = btoa(data);

    blockchain.addBlock(new Block(
        blockchain.getLatestBlock().index + 1,
        blockchain.getLatestBlock().hash,
        encryptedData,
        Math.floor(new Date().getTime() / 1000),
        0
    ));

    // Print blockchain information (you can remove this in a real application)
    console.log("Current Blockchain:", blockchain);

    // Save blockchain to a file (you need server-side code to handle file saving in a real application)
    blockchain.saveToLocalStorage();
    blockchain.loadFromLocalStorage(localStorage.getItem('blockchain'));

    // Clear the form
    document.getElementById("blockchainForm").reset();
}


// Block class
function Block(index, previousHash, data, timestamp, nonce) {
    this.index = index;
    this.previousHash = previousHash;
    this.data = data;
    this.timestamp = timestamp;
    this.nonce = nonce;
    this.hash = this.calculateHash();
}


// Calculate hash function
Block.prototype.calculateHash = function () {
    return CryptoJS.MD5(
        this.index +
        this.previousHash +
        this.data +
        this.timestamp +
        this.nonce
    ).toString();
};


function decryptBlockchain(encryptedData, secretKey) {
    try {
        const key = CryptoJS.MD5(secretKey).toString();
        const decryptedData = CryptoJS.AES.decrypt(encryptedData, key, {
            mode: CryptoJS.mode.CFB,
            padding: CryptoJS.pad.Pkcs7,
        });

        const decryptedString = decodeURIComponent(CryptoJS.enc.Utf8.stringify(decryptedData));

        try {
            // Attempt to parse decrypted string as JSON
            return JSON.parse(decryptedString);
        } catch (jsonError) {
            console.warn("Failed to parse decrypted string as JSON:", jsonError);
            return null;
        }
    } catch (error) {
        console.error("Error during decryption( Your password is probably incorrect ):", error);
        return null;
    }
}




let globalChain;

// Blockchain class
function Blockchain(secretKey = document.getElementById("key_input").value.trim()) {
    const storedChain = localStorage.getItem(blockchainName);
    console.log(storedChain)
    
    if (storedChain){;
        let decryptedChain;

        try {
            // Check if the key is present
            if (secretKey) {
                // Use the key in your application logic
                console.log("Secret Key:", secretKey);
            } else {
                // If the key is not present, handle the situation accordingly
                console.log("Invalid or missing secret key. Please go back to the control page.")
                alert("Invalid or missing secret key. Please go back to the control page.");
            }
            decryptedChain = decryptBlockchain(storedChain, secretKey);
        } catch (error) {
            console.error("Error during blockchain decryption:", error);
        }

        this.chain = decryptedChain ? decryptedChain : [this.createGenesisBlock()];
        globalChain = this.chain
    } 
    else {
        this.chain = [this.createGenesisBlock()]
        globalChain = this.chain
    }
}


// Create genesis block
Blockchain.prototype.createGenesisBlock = function () {
    return new Block(0, "0", "NDU2Nzg5MDEyMzQ1Njc4OXxHZW5lc2lzIEJsb2NrfDA1fDIwMjR8MTIz", Math.floor(new Date().getTime() / 1000), 0);
};

// Get latest block

Blockchain.prototype.getLatestBlock = function () {
    return this.chain[this.chain.length - 1];
};


// Add block to the blockchain
Blockchain.prototype.addBlock = function (newBlock) {
    newBlock.previousHash = this.getLatestBlock().hash;
    newBlock.hash = newBlock.calculateHash();
    this.chain.push(newBlock);
};

// Check if the chain is valid
Blockchain.prototype.isChainValid = function () {
    for (let i = 1; i < this.chain.length; i++) {
        const currentBlock = this.chain[i];
        const previousBlock = this.chain[i - 1];

        if (currentBlock.hash !== currentBlock.calculateHash()) {
            console.log(1);
            return false;
        }

        if (currentBlock.previousHash !== previousBlock.hash) {
            console.log(2);
            return false;
        }
    }
    return true;
};

// Get block by hash
Blockchain.prototype.getBlockByHash = function (targetHash) {
    for (const block of this.chain) {
        if (block.hash === targetHash) {
            return block;
        }
    }
    return null;
};

// Save blockchain to a file
Blockchain.prototype.saveToLocalStorage = function () {
    localStorage.setItem(blockchainName, JSON.stringify(this.chain));
    console.log(blockchain)
    console.log(JSON.stringify(this.chain))
};

// Load blockchain from a file
Blockchain.prototype.loadFromLocalStorage = function (storedChain) {
    const serializedChain = JSON.parse(storedChain);
    const blockchain = new Blockchain();

    serializedChain.forEach(serializedBlock => {
        const block = blockchain.getBlockByHash(serializedBlock.hash);
        if (!block) {
            const newBlock = new Block(
                serializedBlock.index,
                serializedBlock.previousHash,
                serializedBlock.data,
                serializedBlock.timestamp,
                serializedBlock.nonce
            );
            newBlock.hash = serializedBlock.hash;
            blockchain.chain.push(newBlock);
        }
    });

    // Update the current instance's chain
    this.chain = blockchain.chain;
    console.log("Loaded file.")
    console.log(this.chain)
}

function decodeAndSplitData(inputData) {
    return inputData.map(item => {
        // Base64'den çözülen veriyi UTF-8 olarak işle
        const decodedData = decodeURIComponent(escape(atob(item.data)));

        const [creditCard, cardName, cardMonth, cardYear, cardCvv] = decodedData.split('|');

        if (cardName === "Genesis Block" && inputData.length > 1) {
            return null;
        }

        return {
            id: item.index,
            cardName: decodeURIComponent(cardName), // Decode cardName
            cardNumber: decodeURIComponent(creditCard),
            cardMonth: cardMonth,
            cardYear: cardYear,
            cardCvv: cardCvv,
            cardType: "",
            flipped: false,
            showFullNumber: false,
            rotateY: 0,
            visible: true
        };
    }).filter(item => item !== null);
}

  


//   {
//     id: 1,
//     cardName: "Burak Erdogan",
//     cardNumber: "592610252594907",
//     cardMonth: "05",
//     cardYear: "2025",
//     cardCvv: "741",
//     cardType: "",
//     flipped: false,
//     showFullNumber: false,
//     rotateY: 0,
//     visible: true
//   }