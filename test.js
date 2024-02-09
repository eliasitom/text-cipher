import CryptoJS from "crypto-js";

const encryptText = (text, password) => {
    const salt = CryptoJS.lib.WordArray.random(128 / 8); // Generate a random salt
    const key = CryptoJS.PBKDF2(password, salt, { keySize: 256 / 32, iterations: 1000 }); // Derive key using PBKDF2

    const encryptedText = CryptoJS.AES.encrypt(text, key, { iv: salt }).toString(); // Encrypt text using AES with the derived key

    return encryptedText;
};

const decryptText = (encryptedText, password) => {
    const bytes = CryptoJS.AES.decrypt(encryptedText, password); // Decrypt text using the provided password
    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);

    return decryptedText;
};


const password = 'tu_contraseña_segura';
const originalText = 'Texto a encriptar';

const encryptedText = encryptText(originalText, password);
console.log('Texto encriptado:', encryptedText);

const decryptedText = decryptText(encryptedText, password);
console.log('Texto desencriptado:', decryptedText);
