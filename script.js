
let currentMode = 'email';
let isLoggedIn = false;

// Login Form Elements
const emailModeBtn = document.getElementById('emailModeBtn');
const mobileModeBtn = document.getElementById('mobileModeBtn');
const emailModeFields = document.querySelector('.email-mode-fields');
const mobileModeFields = document.querySelector('.mobile-mode-fields');
const loginForm = document.getElementById('loginForm');
const loginBtn = document.getElementById('loginBtn');
const emailInput = document.getElementById('emailInput');
const passwordInput = document.getElementById('passwordInput');
const mobileInput = document.getElementById('mobileInput');
const togglePassword = document.getElementById('togglePassword');
const alertBox = document.getElementById('alertBox');
const loginPage = document.getElementById('loginPage');
const mainApp = document.getElementById('mainApp');

// Switch between email and mobile login
emailModeBtn.addEventListener('click', () => switchMode('email'));
mobileModeBtn.addEventListener('click', () => switchMode('mobile'));

function switchMode(mode) {
    currentMode = mode;
    if (mode === 'email') {
        emailModeBtn.classList.add('active');
        mobileModeBtn.classList.remove('active');
        emailModeFields.style.display = 'block';
        mobileModeFields.style.display = 'none';
        emailInput.setAttribute('required', 'required');
        passwordInput.setAttribute('required', 'required');
        mobileInput.removeAttribute('required');
    } else {
        mobileModeBtn.classList.add('active');
        emailModeBtn.classList.remove('active');
        mobileModeFields.style.display = 'block';
        emailModeFields.style.display = 'none';
        mobileInput.setAttribute('required', 'required');
        emailInput.removeAttribute('required');
        passwordInput.removeAttribute('required');
    }
    validateInputs();
    hideAlert();
}

// Validate inputs
emailInput.addEventListener('input', validateInputs);
passwordInput.addEventListener('input', validateInputs);
mobileInput.addEventListener('input', validateInputs);

function validateInputs() {
    let isValid = false;
    if (currentMode === 'email') {
        const emailValue = emailInput.value.trim();
        const passwordValue = passwordInput.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        isValid = emailRegex.test(emailValue) && passwordValue.length >= 6;
    } else {
        const mobileValue = mobileInput.value.trim();
        const mobileRegex = /^[0-9]{10}$/;
        isValid = mobileRegex.test(mobileValue);
    }
    loginBtn.disabled = !isValid;
}

// Toggle password visibility
togglePassword.addEventListener('click', () => {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
});

// Login form submission
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (loginBtn.disabled) return;

    loginBtn.disabled = true;
    loginBtn.innerHTML = '<span>Logging in...</span>';

    try {
        await new Promise(resolve => setTimeout(resolve, 1500));

        // Simulate successful login
        showAlert('success', 'Login successful! Redirecting...');

        setTimeout(() => {
            isLoggedIn = true;
            loginPage.style.display = 'none';
            mainApp.style.display = 'block';
        }, 1000);
    } catch (error) {
        showAlert('error', 'Login failed. Please try again.');
        loginBtn.disabled = false;
        loginBtn.innerHTML = '<span>Login</span><svg class="btn-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>';
    }
});

function showAlert(type, message) {
    alertBox.className = `alert-box ${type}`;
    alertBox.textContent = message;
    alertBox.style.display = 'block';
}

function hideAlert() {
    alertBox.style.display = 'none';
}

function logout() {
    isLoggedIn = false;
    loginPage.style.display = 'flex';
    mainApp.style.display = 'none';
    emailInput.value = '';
    passwordInput.value = '';
    mobileInput.value = '';
    loginBtn.disabled = true;
    loginBtn.innerHTML = '<span>Login</span><svg class="btn-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>';
    hideAlert();
}

// Website Security Analysis
function analyzeWebsite() {
    const url = document.getElementById('websiteUrl').value.trim();
    const resultsDiv = document.getElementById('websiteResults');

    if (!url) return;

    let score = 0;
    const strengths = [];
    const concerns = [];

    if (url.toLowerCase().startsWith('https://')) {
        score += 30;
        strengths.push('HTTPS encryption enabled');
    } else {
        concerns.push('No HTTPS detected (use HTTPS for secure communication)');
    }

    if (/\/\/www\./.test(url)) {
        score += 10;
        strengths.push('www subdomain detected');
    } else {
        concerns.push('No www subdomain (recommended for legacy compatibility)');
    }

    if (/\.(com|org|net|edu|gov)$/i.test(url)) {
        score += 10;
        strengths.push('Recognized top-level domain (.com, .org, etc.)');
    } else {
        concerns.push('Unusual or less common TLD');
    }

    concerns.push('Configure a proper Content Security Policy for higher security');
    concerns.push('Ensure X-Frame-Options header is set to prevent clickjacking');

    let riskLevel = score > 35 ? 'low' : (score > 20 ? 'medium' : 'high');
    let safeScore = Math.min(Math.max(score, 0), 50);

    resultsDiv.innerHTML = `
                <div class="result-card ${riskLevel}">
                    <div class="score-header">
                        <span>Risk Level</span>
                        <span class="score-value ${riskLevel}">${riskLevel.toUpperCase()}</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill ${riskLevel}" style="width:${safeScore * 2}%;"></div>
                    </div>
                    <ul class="warning-list">
                        ${concerns.map(c => `<li><span class="warning-dot ${riskLevel}"></span>${c}</li>`).join('')}
                    </ul>
                    <div style="margin-top:1em;color:var(--cyber-cyan);">
                        <strong>Strengths:</strong><br>
                        ${strengths.join('<br>')}
                    </div>
                </div>
            `;
    resultsDiv.classList.remove('hidden');
}

// Email Analysis
function analyzeEmail() {
    const emailContent = document.getElementById('emailContent').value.trim();
    const resultsDiv = document.getElementById('emailResults');

    if (!emailContent) return;

    let risk = 'low', score = 0;
    const redFlags = [];

    const patterns = [
        { word: /click (here|now)/i, desc: 'Suspicious call to action' },
        { word: /urgent/i, desc: 'Urgency language' },
        { word: /verify (your|the) account/i, desc: 'Requests account verification' },
        { word: /password|bank|social security|ssn/i, desc: 'Requests sensitive information' },
        { word: /unusual activity|limited time/i, desc: 'Unusual activity notice' },
        { word: /login (now)?/i, desc: 'Unusual login or login link' },
        { word: /prize|winner|won/i, desc: 'Mentions of prizes or winnings' },
    ];

    if (/\bhttps?:\/\/\S+\b/i.test(emailContent)) {
        score += 15;
        redFlags.push('Links detected (potential malicious URLs)');
    }

    if (/attachment/i.test(emailContent)) {
        score += 10;
        redFlags.push('Mentions of attachments (potential malware)');
    }

    patterns.forEach(p => {
        if (p.word.test(emailContent)) {
            score += 15;
            redFlags.push(p.desc);
        }
    });

    if (score > 40) risk = "high";
    else if (score > 20) risk = "medium";
    else risk = "low";

    resultsDiv.innerHTML = `
                <div class="result-card ${risk}">
                    <div class="score-header">
                        <span>Risk Level</span>
                        <span class="score-value ${risk}">${risk.toUpperCase()}</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill ${risk}" style="width:${Math.min(score, 50) * 2}%;"></div>
                    </div>
                    <ul class="warning-list">
                        ${redFlags.length > 0 ? redFlags.map(c => `<li><span class="warning-dot ${risk}"></span>${c}</li>`).join('') : '<li>No major phishing indicators found.</li>'}
                    </ul>
                    <div style="margin-top:1em;color:var(--cyber-cyan);">
                        <strong>General Advice:</strong><br>
                        Beware of unknown senders and verify links before clicking.
                    </div>
                </div>
            `;
    resultsDiv.classList.remove('hidden');
}

// Caesar Cipher Encryption
function caesarEncrypt(text, shift) {
    const a = 'a'.charCodeAt(0);
    const A = 'A'.charCodeAt(0);
    return text.split('').map(ch => {
        if (ch >= 'a' && ch <= 'z') {
            return String.fromCharCode(a + (ch.charCodeAt(0) - a + shift) % 26);
        } else if (ch >= 'A' && ch <= 'Z') {
            return String.fromCharCode(A + (ch.charCodeAt(0) - A + shift) % 26);
        } else {
            return ch;
        }
    }).join('');
}

function caesarDecrypt(text, shift) {
    return caesarEncrypt(text, 26 - (shift % 26));
}

function handleEncrypt() {
    const text = document.getElementById('encryptText').value;
    let shift = parseInt(document.getElementById('encryptKey').value) || 3;
    const resultDiv = document.getElementById('encryptedResult');
    const resultText = document.getElementById('encryptedText');

    if (!text) return;

    resultText.textContent = caesarEncrypt(text, shift);
    resultDiv.classList.remove('hidden');
}

function handleDecrypt() {
    const text = document.getElementById('decryptText').value;
    let shift = parseInt(document.getElementById('decryptKey').value) || 3;
    const resultDiv = document.getElementById('decryptedResult');
    const resultText = document.getElementById('decryptedText');

    if (!text) return;

    resultText.textContent = caesarDecrypt(text, shift);
    resultDiv.classList.remove('hidden');
}
