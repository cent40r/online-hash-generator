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

// Control Groups
const bcryptControls = document.getElementById('bcrypt-controls');
const argon2Controls = document.getElementById('argon2-controls');

// Bcrypt Elements
const bcryptModeRadios = document.querySelectorAll('input[name="bcrypt-mode"]');
const bcryptCostFactorWrapper = document.getElementById('bcrypt-cost-factor-wrapper');
const bcryptCostFactorSlider = document.getElementById('bcrypt-cost-factor');
const costFactorValueSpan = document.getElementById('cost-factor-value');
const bcryptVerifyInputWrapper = document.getElementById('bcrypt-verify-input-wrapper');

// Argon2 Elements
const argon2ModeRadios = document.querySelectorAll('input[name="argon2-mode"]');
const argon2HashOptions = document.getElementById('argon2-hash-options');
const argon2VerifyInputWrapper = document.getElementById('argon2-verify-input-wrapper');
const argon2GenerateSaltBtn = document.getElementById('argon2-generate-salt');

// UI Titles
const inputTitle = document.getElementById('input-title');
const outputTitle = document.getElementById('output-title');

let bcryptjs = null;
let argon2js = null;

// --- Helper Functions ---
function showLoader(show) { loader.classList.toggle('hidden', !show); generateBtn.classList.toggle('hidden', show); }
function createOutputTextarea(content = '') { const ta = document.createElement('textarea'); ta.id = 'hash-output'; ta.readOnly = true; ta.placeholder = "Your result will appear here..."; ta.value = content; return ta; }
function showOutputMessage(type, message) { outputWrapper.innerHTML = `<div class="output-message ${type}">${message}</div>`; }
function generateRandomSalt(bytes = 16) { const buffer = new Uint8Array(bytes); window.crypto.getRandomValues(buffer); return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join(''); }

// --- Dynamic Library Loaders ---
function loadScript(src) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = () => reject(new Error(`Could not load script: ${src}`));
        document.head.appendChild(script);
    });
}

async function loadBcrypt() {
    if (bcryptjs) return bcryptjs;
    showLoader(true);
    try {
        await loadScript('https://cdn.jsdelivr.net/npm/bcryptjs@2.4.3/dist/bcrypt.min.js');
        bcryptjs = window.dcodeIO.bcrypt;
        return bcryptjs;
    } finally {
        showLoader(false);
    }
}
async function loadArgon2() {
    if (argon2js) return argon2js;
    showLoader(true);
    try {
        await loadScript('https://cdn.jsdelivr.net/npm/argon2-browser/lib/argon2.min.js');
        argon2js = window.argon2;
        return argon2js;
    } finally {
        showLoader(false);
    }
}

// --- UI Logic ---
function updateUIForAlgorithm(algorithm) {
    const isBcrypt = algorithm === 'Bcrypt';
    const isArgon2 = algorithm === 'Argon2';
    bcryptControls.classList.toggle('hidden', !isBcrypt);
    argon2Controls.classList.toggle('hidden', !isArgon2);
    fileInput.parentElement.classList.toggle('hidden', isBcrypt || isArgon2);

    if (!isBcrypt && !isArgon2) { // Standard Hash
        inputTitle.textContent = 'Input';
        outputTitle.textContent = 'Hash Output';
        textInput.placeholder = 'Type or paste your text here...';
        generateBtn.textContent = 'Generate';
        if (!document.getElementById('hash-output')) { outputWrapper.innerHTML = ''; outputWrapper.appendChild(createOutputTextarea()); }
    } else if (isBcrypt) {
        updateUIForBcryptMode();
    } else if (isArgon2) {
        updateUIForArgon2Mode();
    }
}

function updateUIForBcryptMode() {
    const selectedMode = document.querySelector('input[name="bcrypt-mode"]:checked').value;
    const isHashMode = selectedMode === 'hash';
    bcryptCostFactorWrapper.classList.toggle('hidden', !isHashMode);
    bcryptVerifyInputWrapper.classList.toggle('hidden', isHashMode);
    outputTitle.textContent = isHashMode ? 'Bcrypt Hash Output' : 'Verification Result';
    inputTitle.textContent = isHashMode ? 'Password to Hash' : 'Password to Check';
    generateBtn.textContent = isHashMode ? 'Generate Hash' : 'Verify';
    if (isHashMode) { if (!document.getElementById('hash-output')) { outputWrapper.innerHTML = ''; outputWrapper.appendChild(createOutputTextarea()); } }
    else { outputWrapper.innerHTML = '<div class="output-message">Result will be shown here.</div>'; }
}

function updateUIForArgon2Mode() {
    const selectedMode = document.querySelector('input[name="argon2-mode"]:checked').value;
    const isHashMode = selectedMode === 'hash';
    argon2HashOptions.classList.toggle('hidden', !isHashMode);
    argon2VerifyInputWrapper.classList.toggle('hidden', isHashMode);
    outputTitle.textContent = isHashMode ? 'Argon2 Hash Output' : 'Verification Result';
    inputTitle.textContent = isHashMode ? 'Password to Hash' : 'Password to Check';
    generateBtn.textContent = isHashMode ? 'Generate Hash' : 'Verify';
    if (isHashMode) { if (!document.getElementById('hash-output')) { outputWrapper.innerHTML = ''; outputWrapper.appendChild(createOutputTextarea()); } }
    else { outputWrapper.innerHTML = '<div class="output-message">Result will be shown here.</div>'; }
}

// --- Event Listeners ---
algorithmSelect.addEventListener('change', () => updateUIForAlgorithm(algorithmSelect.value));
bcryptModeRadios.forEach(radio => radio.addEventListener('change', updateUIForBcryptMode));
bcryptCostFactorSlider.addEventListener('input', () => costFactorValueSpan.textContent = bcryptCostFactorSlider.value);
argon2ModeRadios.forEach(radio => radio.addEventListener('change', updateUIForArgon2Mode));
argon2GenerateSaltBtn.addEventListener('click', () => document.getElementById('argon2-salt').value = generateRandomSalt());
generateBtn.addEventListener('click', handleGenerateClick);
clearFileBtn.addEventListener('click', () => { fileInput.value = ''; fileInfo.classList.add('hidden'); });

fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const MAX_FILE_SIZE_MB = 10;
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

// --- Hashing Logic ---
async function handleGenerateClick() {
    const algorithm = algorithmSelect.value;
    
    try {
        if (algorithm === 'Bcrypt') {
            const bcrypt = await loadBcrypt();
            await handleBcrypt(bcrypt);
        } else if (algorithm === 'Argon2') {
            const argon2 = await loadArgon2();
            await handleArgon2(argon2);
        } else {
            handleStandardHash();
        }
    } catch (error) {
        alert(error.message);
        showLoader(false);
    }
}

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
            case 'SHA3-512': hash = CryptoJS.SHA3(inputText, { outputLength: 512 }).toString(); break;
            case 'SHA224': hash = CryptoJS.SHA224(inputText).toString(); break;
            case 'SHA384': hash = CryptoJS.SHA384(inputText).toString(); break;
            case 'RIPEMD160': hash = CryptoJS.RIPEMD160(inputText).toString(); break;
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
    if (!plaintext) { alert('Please enter a password.'); return; }
    
    showLoader(true);
    await new Promise(resolve => setTimeout(resolve, 50));

    if (selectedMode === 'hash') {
        const costFactor = parseInt(bcryptCostFactorSlider.value, 10);
        bcrypt.hash(plaintext, costFactor, (err, hash) => { showLoader(false); if(err){alert('Error: '+err); return;} if (!document.getElementById('hash-output')) { outputWrapper.innerHTML = ''; outputWrapper.appendChild(createOutputTextarea()); } document.getElementById('hash-output').value = hash; });
    } else {
        const hashToCompare = document.getElementById('bcrypt-hash-input').value;
        if (!hashToCompare) { alert('Please enter the hash to compare.'); showLoader(false); return; }
        bcrypt.compare(plaintext, hashToCompare, (err, result) => { showLoader(false); if(err){showOutputMessage('error', '❌ Invalid Hash Format'); return;} showOutputMessage(result ? 'success' : 'error', result ? '✅ Match!' : '❌ No Match'); });
    }
}

async function handleArgon2(argon2) {
    const selectedMode = document.querySelector('input[name="argon2-mode"]:checked').value;
    const plaintext = textInput.value;
    if (!plaintext) { alert('Please enter a password.'); showLoader(false); return; }
    
    showLoader(true);
    await new Promise(resolve => setTimeout(resolve, 50));

    if (selectedMode === 'hash') {
        const salt = document.getElementById('argon2-salt').value || generateRandomSalt();
        document.getElementById('argon2-salt').value = salt;
        const options = {
            pass: plaintext,
            salt: salt,
            time: parseInt(document.getElementById('argon2-iterations').value, 10),
            mem: parseInt(document.getElementById('argon2-mem').value, 10),
            parallelism: parseInt(document.getElementById('argon2-parallelism').value, 10),
            hashLen: parseInt(document.getElementById('argon2-hash-len').value, 10),
            type: argon2.ArgonType[document.getElementById('argon2-type').value],
        };
        try {
            const hashResult = await argon2.hash(options);
            if (!document.getElementById('hash-output')) { outputWrapper.innerHTML = ''; outputWrapper.appendChild(createOutputTextarea()); }
            document.getElementById('hash-output').value = hashResult.encoded;
        } catch(e) { alert('Error generating Argon2 hash: ' + e.message); }
        finally { showLoader(false); }
    } else {
        const encodedHash = document.getElementById('argon2-hash-input').value;
        if (!encodedHash) { alert('Please enter the encoded hash to compare.'); showLoader(false); return; }
        try {
            const match = await argon2.verify({ pass: plaintext, encoded: encodedHash });
            showOutputMessage(match ? 'success' : 'error', match ? '✅ Match!' : '❌ No Match');
        } catch(e) { showOutputMessage('error', '❌ Verification Error: ' + e.message); }
        finally { showLoader(false); }
    }
}

// Initial UI setup on page load
updateUIForAlgorithm(algorithmSelect.value);