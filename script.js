// --- Self-contained Hashing Functions ---
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

function adler32(str) {
    const MOD_ADLER = 65521;
    let a = 1, b = 0;
    for (let i = 0; i < str.length; i++) {
        a = (a + str.charCodeAt(i)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    return (b << 16) | a;
}

// --- DOM Element References ---
const textInput = document.getElementById('text-input');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const fileNameSpan = document.getElementById('file-name');
const clearFileBtn = document.getElementById('clear-file-btn');
const algorithmSelect = document.getElementById('hash-algorithm');
const generateBtn = document.getElementById('generate-btn');
const outputWrapper = document.getElementById('output-wrapper');
const loader = document.getElementById('loader');

// Bcrypt specific elements
const bcryptControls = document.getElementById('bcrypt-controls');
const bcryptModeRadios = document.querySelectorAll('input[name="bcrypt-mode"]');
const bcryptCostFactorWrapper = document.getElementById('bcrypt-cost-factor-wrapper');
const bcryptCostFactorSlider = document.getElementById('bcrypt-cost-factor');
const costFactorValueSpan = document.getElementById('cost-factor-value');
const bcryptVerifyInputWrapper = document.getElementById('bcrypt-verify-input-wrapper');
const inputTitle = document.getElementById('input-title');
const outputTitle = document.getElementById('output-title');

const MAX_FILE_SIZE_MB = 10;
let bcryptjs = null; // Variable to hold the bcryptjs library once loaded

// --- Helper Functions ---
function showLoader(show) {
    loader.classList.toggle('hidden', !show);
    generateBtn.classList.toggle('hidden', show);
}

function createOutputTextarea(content = '') {
    const textarea = document.createElement('textarea');
    textarea.id = 'hash-output';
    textarea.readOnly = true;
    textarea.placeholder = "Your result will appear here...";
    textarea.value = content;
    return textarea;
}

function showOutputMessage(type, message) {
    outputWrapper.innerHTML = `<div class="output-message ${type}">${message}</div>`;
}

// --- Dynamic Bcrypt Library Loader ---
function loadBcrypt() {
    if (bcryptjs) return Promise.resolve(bcryptjs); // Already loaded

    showLoader(true);
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/bcryptjs@2.4.3/dist/bcrypt.min.js';
        script.onload = () => {
            bcryptjs = window.dcodeIO.bcrypt;
            showLoader(false);
            resolve(bcryptjs);
        };
        script.onerror = () => {
            showLoader(false);
            reject(new Error('Could not load bcrypt library. Please check your internet connection.'));
        };
        document.head.appendChild(script);
    });
}

// --- UI Logic ---
function updateUIForAlgorithm(algorithm) {
    const isBcrypt = algorithm === 'Bcrypt';
    bcryptControls.classList.toggle('hidden', !isBcrypt);
    fileInput.parentElement.classList.toggle('hidden', isBcrypt);
    
    // Restore UI to normal if not bcrypt
    if (!isBcrypt) {
        inputTitle.textContent = 'Input';
        outputTitle.textContent = 'Hash Output';
        textInput.placeholder = 'Type or paste your text here...';
        generateBtn.textContent = 'Generate';
        if (!document.getElementById('hash-output')) {
            outputWrapper.innerHTML = '';
            outputWrapper.appendChild(createOutputTextarea());
        }
    } else {
        updateUIForBcryptMode();
    }
}

function updateUIForBcryptMode() {
    const selectedMode = document.querySelector('input[name="bcrypt-mode"]:checked').value;
    const isHashMode = selectedMode === 'hash';

    bcryptCostFactorWrapper.classList.toggle('hidden', !isHashMode);
    bcryptVerifyInputWrapper.classList.toggle('hidden', isHashMode);
    
    outputTitle.textContent = isHashMode ? 'Bcrypt Hash Output' : 'Verification Result';
    inputTitle.textContent = isHashMode ? 'Password to Hash' : 'Password to Check';
    textInput.placeholder = isHashMode ? 'Enter the password to hash...' : 'Enter the plaintext password...';
    generateBtn.textContent = isHashMode ? 'Generate Hash' : 'Verify';
    
    if (isHashMode) {
        if (!document.getElementById('hash-output')) {
             outputWrapper.innerHTML = '';
             outputWrapper.appendChild(createOutputTextarea());
        }
    } else {
        outputWrapper.innerHTML = '<div class="output-message">Result will be shown here.</div>';
    }
}

// --- Event Listeners ---
algorithmSelect.addEventListener('change', () => {
    updateUIForAlgorithm(algorithmSelect.value);
});

bcryptModeRadios.forEach(radio => {
    radio.addEventListener('change', updateUIForBcryptMode);
});

bcryptCostFactorSlider.addEventListener('input', () => {
    costFactorValueSpan.textContent = bcryptCostFactorSlider.value;
});

fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
        alert(`File is too large. Max size: ${MAX_FILE_SIZE_MB}MB.`);
        clearFile(); return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
        textInput.value = e.target.result;
        fileNameSpan.textContent = file.name;
        fileInfo.classList.remove('hidden');
    };
    reader.onerror = () => { alert('Error reading file.'); clearFile(); };
    reader.readAsText(file);
});

function clearFile() {
    fileInput.value = '';
    fileNameSpan.textContent = '';
    fileInfo.classList.add('hidden');
}
clearFileBtn.addEventListener('click', clearFile);

generateBtn.addEventListener('click', async () => {
    const algorithm = algorithmSelect.value;
    if (algorithm === 'Bcrypt') {
        try {
            const bcrypt = await loadBcrypt();
            handleBcrypt(bcrypt);
        } catch (error) {
            alert(error.message);
        }
    } else {
        handleStandardHash();
    }
});

// --- Hashing Logic ---
function handleStandardHash() {
    const inputText = textInput.value;
    const algorithm = algorithmSelect.value;
    if (inputText.length === 0) {
        alert('Input is empty.'); return;
    }
    try {
        let hash;
        switch (algorithm) {
            case 'MD5': hash = CryptoJS.MD5(inputText).toString(); break;
            case 'SHA1': hash = CryptoJS.SHA1(inputText).toString(); break;
            case 'SHA256': hash = CryptoJS.SHA256(inputText).toString(); break;
            case 'SHA512': hash = CryptoJS.SHA512(inputText).toString(); break;
            case 'SHA224': hash = CryptoJS.SHA224(inputText).toString(); break;
            case 'SHA384': hash = CryptoJS.SHA384(inputText).toString(); break;
            case 'RIPEMD160': hash = CryptoJS.RIPEMD160(inputText).toString(); break;
            case 'SHA3-512': hash = CryptoJS.SHA3(inputText, { outputLength: 512 }).toString(); break;
            case 'CRC16': hash = crc16(inputText).toString(16); break;
            case 'CRC32': hash = crc32(inputText).toString(16); break;
            case 'Adler32': hash = adler32(inputText).toString(16); break;
            default: hash = 'Algorithm not supported.';
        }
        document.getElementById('hash-output').value = hash;
    } catch (error) {
        console.error('Hashing error:', error);
        alert(`An error occurred: ${error.message}`);
    }
}

async function handleBcrypt(bcrypt) {
    const selectedMode = document.querySelector('input[name="bcrypt-mode"]:checked').value;
    const plaintext = textInput.value;

    if (!plaintext) {
        alert('Please enter a password.');
        return;
    }

    showLoader(true);

    // Use a small timeout to allow the UI to update and show the loader before the heavy computation starts
    setTimeout(() => {
        if (selectedMode === 'hash') {
            const costFactor = parseInt(bcryptCostFactorSlider.value, 10);
            bcrypt.hash(plaintext, costFactor, (err, hash) => {
                showLoader(false);
                if (err) {
                    alert('Error generating hash: ' + err);
                    return;
                }
                if (!document.getElementById('hash-output')) {
                    outputWrapper.innerHTML = '';
                    outputWrapper.appendChild(createOutputTextarea(hash));
                } else {
                    document.getElementById('hash-output').value = hash;
                }
            });
        } else { // Verify mode
            const hashToCompare = document.getElementById('bcrypt-hash-input').value;
            if (!hashToCompare) {
                alert('Please enter the hash to compare against.');
                showLoader(false);
                return;
            }
            bcrypt.compare(plaintext, hashToCompare, (err, result) => {
                showLoader(false);
                if (err) {
                    alert('Error verifying hash: ' + err);
                    showOutputMessage('error', '❌ Error during verification. Make sure the hash format is correct.');
                    return;
                }
                if (result === true) {
                    showOutputMessage('success', '✅ Match!');
                } else {
                    showOutputMessage('error', '❌ No Match');
                }
            });
        }
    }, 50); // 50ms timeout
}

// Initial UI setup on page load
updateUIForAlgorithm(algorithmSelect.value);