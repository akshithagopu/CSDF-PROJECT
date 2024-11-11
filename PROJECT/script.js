// AES Encryption & Decryption with CryptoJS
function encryptAES() {
    const text = document.getElementById("aes-text").value;
    const key = document.getElementById("aes-key").value;
    if (text && key) {
      const encrypted = CryptoJS.AES.encrypt(text, key).toString();
      document.getElementById("aes-output").value = encrypted;
    } else {
      alert("Please enter text and key for AES encryption.");
    }
  }
  
  function decryptAES() {
    const encryptedText = document.getElementById("aes-text").value;
    const key = document.getElementById("aes-key").value;
    if (encryptedText && key) {
      const bytes = CryptoJS.AES.decrypt(encryptedText, key);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      document.getElementById("aes-output").value = decrypted || "Invalid key!";
    } else {
      alert("Please enter encrypted text and key for AES decryption.");
    }
  }
  
  // RSA Encryption & Decryption (simplified)
  let publicKey, privateKey;
  function generateRSAKeys() {
    // Use a simplified key pair for demonstration
    const { publicKey: pubKey, privateKey: privKey } = forge.pki.rsa.generateKeyPair(512);
    publicKey = pubKey;
    privateKey = privKey;
    alert("RSA Keys generated successfully!");
  }
  
  function encryptRSA() {
    const text = document.getElementById("rsa-text").value;
    if (text && publicKey) {
      const encrypted = publicKey.encrypt(forge.util.encodeUtf8(text));
      document.getElementById("rsa-output").value = forge.util.encode64(encrypted);
    } else {
      alert("Please enter text and generate RSA keys.");
    }
  }
  
  function decryptRSA() {
    const encryptedText = document.getElementById("rsa-text").value;
    if (encryptedText && privateKey) {
      const decrypted = privateKey.decrypt(forge.util.decode64(encryptedText));
      document.getElementById("rsa-output").value = forge.util.decodeUtf8(decrypted);
    } else {
      alert("Please enter encrypted text and generate RSA keys.");
    }
  }
  
  // Caesar Cipher Encryption & Decryption
  function encryptCaesar() {
    const text = document.getElementById("caesar-text").value;
    const shift = parseInt(document.getElementById("caesar-shift").value, 10);
    document.getElementById("caesar-output").value = caesarCipher(text, shift);
  }
  
  function decryptCaesar() {
    const text = document.getElementById("caesar-text").value;
    const shift = parseInt(document.getElementById("caesar-shift").value, 10);
    document.getElementById("caesar-output").value = caesarCipher(text, -shift);
  }
  
  function caesarCipher(text, shift) {
    return text.replace(/[a-z]/gi, (char) => {
      const start = char <= 'Z' ? 65 : 97;
      return String.fromCharCode((char.charCodeAt(0) - start + shift + 26) % 26 + start);
    });
  }
  