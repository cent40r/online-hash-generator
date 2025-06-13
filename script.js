// --- Self-contained Hashing Functions (No external libraries needed for these) ---

// CRC-32
function crc32(str) {
    let crc = -1;
    for (let i = 0, iTop = str.length; i < iTop; i++) {
        crc = (crc >>> 8) ^ crc32_table[(crc ^ str.charCodeAt(i)) & 0xFF];
    }
    return (crc ^ -1) >>> 0;
};
const crc32_table = (() => {
    let c, table = [];
    for (let n = 0; n < 256; n++) {
        c = n;
        for (let k = 0; k < 8; k++) {
            c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
        }
        table[n] = c;
    }
    return table;
})();

// CRC-16 (Kermit)
function crc16(str) {
    let crc = 0;
    for (let i = 0; i < str.length; i++) {
        let c = str.charCodeAt(i);
        let q = (crc ^ c) & 0x0f;
        crc = (crc >> 4) ^ (q * 0x1081);
        q = (crc ^ (c >> 4)) & 0x0f;
        crc = (crc >> 4) ^ (q * 0x1081);
    }
    return crc & 0xFFFF;
}

// Adler-32
function adler32(str) {
    const MOD_ADLER = 65521;
    let a = 1, b = 0;
    for (let i = 0; i < str.length; i++) {
        a = (a + str.charCodeAt(i)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    return (b << 16) | a;
}

// --- DOM Element References (Executing directly, no 'DOMContentLoaded' needed) ---
const textInput = document.getElementById('text-input');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const fileNameSpan = document.getElementById('file-name');
const clearFileBtn = document.getElementById('clear-file-btn');
const algorithmSelect = document.getElementById('hash-algorithm');
const generateBtn = document.getElementById('generate-btn');
const hashOutput = document.getElementById('hash-output');

const MAX_FILE_SIZE_MB = 10;

// --- Event Listeners ---
fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
        alert(`File is too large. Please select a file smaller than ${MAX_FILE_SIZE_MB}MB.`);
        clearFile(); return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
        textInput.value = e.target.result;
        fileNameSpan.textContent = file.name;
        fileInfo.classList.remove('hidden');
    };
    reader.onerror = () => { alert('Error reading the file.'); clearFile(); };
    reader.readAsText(file);
});

clearFileBtn.addEventListener('click', clearFile);
generateBtn.addEventListener('click', generateHash);

// --- Core Functions ---
function clearFile() {
    fileInput.value = '';
    fileNameSpan.textContent = '';
    fileInfo.classList.add('hidden');
}

function generateHash() {
    const inputText = textInput.value;
    const algorithm = algorithmSelect.value;
    if (inputText.length === 0) {
        hashOutput.value = 'Input is empty. Please type text or upload a file.'; return;
    }
    try {
        let hash;
        switch (algorithm) {
            case 'MD5':       hash = CryptoJS.MD5(inputText).toString(); break;
            case 'SHA1':      hash = CryptoJS.SHA1(inputText).toString(); break;
            case 'SHA256':    hash = CryptoJS.SHA256(inputText).toString(); break;
            case 'SHA512':    hash = CryptoJS.SHA512(inputText).toString(); break;
            case 'SHA224':    hash = CryptoJS.SHA224(inputText).toString(); break;
            case 'SHA384':    hash = CryptoJS.SHA384(inputText).toString(); break;
            case 'SHA3-224':  hash = CryptoJS.SHA3(inputText, { outputLength: 224 }).toString(); break;
            case 'SHA3-256':  hash = CryptoJS.SHA3(inputText, { outputLength: 256 }).toString(); break;
            case 'SHA3-384':  hash = CryptoJS.SHA3(inputText, { outputLength: 384 }).toString(); break;
            case 'SHA3-512':  hash = CryptoJS.SHA3(inputText, { outputLength: 512 }).toString(); break;
            case 'RIPEMD160': hash = CryptoJS.RIPEMD160(inputText).toString(); break;
            
            // Calling local functions
            case 'CRC16':     hash = crc16(inputText).toString(16); break;
            case 'CRC32':     hash = crc32(inputText).toString(16); break;
            case 'Adler32':   hash = adler32(inputText).toString(16); break;
            
            default: hash = 'Selected algorithm is not supported.';
        }
        hashOutput.value = hash;
    } catch (error) {
        console.error('Hashing error:', error);
        hashOutput.value = `An error occurred while generating the hash: ${error.message}`;
    }
}