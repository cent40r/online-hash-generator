function crc32(str) {
    let crc = -1;
    for (let i = 0, iTop = str.length; i < iTop; i++) {
        crc = (crc >>> 8) ^ crc32_table[(crc ^ str.charCodeAt(i)) & 0xFF];
    }
    return (crc ^ -1) >>> 0;
}
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

const textInput = document.getElementById('text-input');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const fileNameSpan = document.getElementById('file-name');
const clearFileBtn = document.getElementById('clear-file-btn');
const algorithmSelect = document.getElementById('hash-algorithm');
const generateBtn = document.getElementById('generate-btn');
const outputWrapper = document.getElementById('output-wrapper');
const loader = document.getElementById('loader');

const bcryptControls = document.getElementById('bcrypt-controls');
const argon2Controls = document.getElementById('argon2-controls');

const bcryptModeRadios = document.querySelectorAll('input[name="bcrypt-mode"]');
const bcryptCostFactorWrapper = document.getElementById('bcrypt-cost-factor-wrapper');
const bcryptCostFactorSlider = document.getElementById('bcrypt-cost-factor');
const costFactorValueSpan = document.getElementById('cost-factor-value');
const bcryptVerifyInputWrapper = document.getElementById('bcrypt-verify-input-wrapper');

const argon2ModeRadios = document.querySelectorAll('input[name="argon2-mode"]');
const argon2HashOptions = document.getElementById('argon2-hash-options');
const argon2VerifyInputWrapper = document.getElementById('argon2-verify-input-wrapper');
const argon2GenerateSaltBtn = document.getElementById('argon2-generate-salt');

const inputTitle = document.getElementById('input-title');
const outputTitle = document.getElementById('output-title');

const bcryptjs = window.dcodeIO.bcrypt;
const argon2 = window.argon2;

function showLoader(show) {
    loader.classList.toggle('hidden', !show);
    generateBtn.classList.toggle('hidden', show);
}

function createOutputTextarea(content = '') {
    const ta = document.createElement('textarea');
    ta.id = 'hash-output';
    ta.readOnly = true;
    ta.placeholder = "Your result will appear here...";
    ta.value = content;
    return ta;
}

function showOutputMessage(type, message) {
    outputWrapper.innerHTML = `<div class="output-message ${type}">${message}</div>`;
}

function generateRandomSalt(bytes = 16) {
    const buffer = new Uint8Array(bytes);
    window.crypto.getRandomValues(buffer);
    return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
}

function updateUIForAlgorithm(algorithm) {
    const isBcrypt = algorithm === 'Bcrypt';
    const isArgon2 = algorithm === 'Argon2';
    bcryptControls.classList.toggle('hidden', !isBcrypt);
    argon2Controls.classList.toggle('hidden', !isArgon2);
    fileInput.parentElement.classList.toggle('hidden', isBcrypt || isArgon2);

    if (!isBcrypt && !isArgon2) {
        inputTitle.textContent = 'Input';
        outputTitle.textContent = 'Hash Output';
        textInput.placeholder = 'Type or paste your text here...';
        generateBtn.textContent = 'Generate';
        if (!document.getElementById('hash-output')) {
            outputWrapper.innerHTML = '';
            outputWrapper.appendChild(createOutputTextarea());
        }
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
    if (isHashMode) {
        if (!document.getElementById('hash-output')) {
            outputWrapper.innerHTML = '';
            outputWrapper.appendChild(createOutputTextarea());
        }
    } else {
        outputWrapper.innerHTML = '<div class="output-message">Result will be shown here.</div>';
    }
}

function updateUIForArgon2Mode() {
    const selectedMode = document.querySelector('input[name="argon2-mode"]:checked').value;
    const isHashMode = selectedMode === 'hash';
    argon2HashOptions.classList.toggle('hidden', !isHashMode);
    argon2VerifyInputWrapper.classList.toggle('hidden', isHashMode);
    outputTitle.textContent = isHashMode ? 'Argon2 Hash Output' : 'Verification Result';
    inputTitle.textContent = isHashMode ? 'Password to Hash' : 'Password to Check';
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

async function handleGenerateClick() {
    const algorithm = algorithmSelect.value;
    showLoader(true);
    await new Promise(resolve => setTimeout(resolve, 50));
    try {
        if (algorithm === 'Bcrypt') {
            await handleBcrypt();
        } else if (algorithm === 'Argon2') {
            await handleArgon2();
        } else {
            handleStandardHash();
        }
    } catch (error) {
        alert(error.message);
    } finally {
        showLoader(false);
    }
}

function handleStandardHash() {
    const inputText = textInput.value;
    const algorithm = algorithmSelect.value;
    if (inputText.length === 0) {
        alert('Input is empty.');
        return;
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
        let outputTextarea = document.getElementById('hash-output');
        if (!outputTextarea) {
            outputWrapper.innerHTML = '';
            outputTextarea = createOutputTextarea();
            outputWrapper.appendChild(outputTextarea);
        }
        outputTextarea.value = hash;
    } catch (error) {
        console.error('Hashing error:', error);
        alert(`An error occurred: ${error.message}`);
    }
}

async function handleBcrypt() {
    const selectedMode = document.querySelector('input[name="bcrypt-mode"]:checked').value;
    const plaintext = textInput.value;
    if (!plaintext) {
        alert('Please enter a password.');
        return;
    }
    if (selectedMode === 'hash') {
        const costFactor = parseInt(bcryptCostFactorSlider.value, 10);
        bcryptjs.hash(plaintext, costFactor, (err, hash) => {
            if (err) {
                alert('Error: ' + err);
                return;
            }
            let outputTextarea = document.getElementById('hash-output');
            if (!outputTextarea) {
                outputWrapper.innerHTML = '';
                outputTextarea = createOutputTextarea();
                outputWrapper.appendChild(outputTextarea);
            }
            outputTextarea.value = hash;
        });
    } else {
        const hashToCompare = document.getElementById('bcrypt-hash-input').value;
        if (!hashToCompare) {
            alert('Please enter the hash to compare.');
            return;
        }
        bcryptjs.compare(plaintext, hashToCompare, (err, result) => {
            if (err) {
                showOutputMessage('error', '❌ Invalid Hash Format');
                return;
            }
            showOutputMessage(result ? 'success' : 'error', result ? '✅ Match!' : '❌ No Match');
        });
    }
}

async function handleArgon2() {
    const selectedMode = document.querySelector('input[name="argon2-mode"]:checked').value;
    const plaintext = textInput.value;
    if (!plaintext) {
        alert('Please enter a password.');
        return;
    }

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
            let outputTextarea = document.getElementById('hash-output');
            if (!outputTextarea) {
                outputWrapper.innerHTML = '';
                outputTextarea = createOutputTextarea();
                outputWrapper.appendChild(outputTextarea);
            }
            outputTextarea.value = hashResult.encoded;
        } catch (e) {
            alert('Error generating Argon2 hash: ' + e.message);
        }
    } else {
        const encodedHash = document.getElementById('argon2-hash-input').value;
        if (!encodedHash) {
            alert('Please enter the encoded hash to compare.');
            return;
        }
        try {
            const match = await argon2.verify({ pass: plaintext, encoded: encodedHash });
            showOutputMessage(match ? 'success' : 'error', match ? '✅ Match!' : '❌ No Match');
        } catch (e) {
            showOutputMessage('error', '❌ Verification Error: ' + e.message);
        }
    }
}

function initialize() {
    algorithmSelect.addEventListener('change', () => updateUIForAlgorithm(algorithmSelect.value));
    generateBtn.addEventListener('click', handleGenerateClick);
    bcryptModeRadios.forEach(radio => radio.addEventListener('change', updateUIForBcryptMode));
    bcryptCostFactorSlider.addEventListener('input', () => costFactorValueSpan.textContent = bcryptCostFactorSlider.value);
    argon2ModeRadios.forEach(radio => radio.addEventListener('change', updateUIForArgon2Mode));
    argon2GenerateSaltBtn.addEventListener('click', () => document.getElementById('argon2-salt').value = generateRandomSalt());

    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) return;
        const MAX_FILE_SIZE_MB = 10;
        if (file.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
            alert(`File is too large. Max size: ${MAX_FILE_SIZE_MB}MB.`);
            clearFile();
            return;
        }
        const reader = new FileReader();
        reader.onload = (e) => {
            textInput.value = e.target.result;
            fileNameSpan.textContent = file.name;
            fileInfo.classList.remove('hidden');
            const clearBtn = document.getElementById('clear-file-btn');
            if (clearBtn) {
                clearBtn.addEventListener('click', clearFile, { once: true });
            }
        };
        reader.onerror = () => {
            alert('Error reading file.');
            clearFile();
        };
        reader.readAsText(file);
    });

    function clearFile() {
        fileInput.value = '';
        if (fileNameSpan) fileNameSpan.textContent = '';
        if (fileInfo) fileInfo.classList.add('hidden');
    }
    if (clearFileBtn) {
        clearFileBtn.addEventListener('click', clearFile);
    }
    updateUIForAlgorithm(algorithmSelect.value);
}

initialize();