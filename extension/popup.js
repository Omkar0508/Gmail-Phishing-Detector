// Configuration
const CLIENT_ID = '900707367129-4m8g9naaarovgi0vkq4ufjlk3c0mu32r.apps.googleusercontent.com';
const REDIRECT_URI = `https://dopejbjimijnjkeceaacogjneapphlmm.chromiumapp.org`;
const SCOPES = 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify';
const API_BASE_URL = 'http://127.0.0.1:5000';

// DOM Elements
const loginButton = document.getElementById('login');
const scanButton = document.getElementById('scanEmails');
const statusText = document.getElementById('status');
const daysSelect = document.getElementById('days');
const maxEmailsInput = document.getElementById('maxEmails');
const progressContainer = document.querySelector('.progress-container');
const progressBar = document.querySelector('.progress-bar');
const resultsContainer = document.querySelector('.results');
const emailsScannedElement = document.getElementById('emailsScanned');
const suspiciousUrlsElement = document.getElementById('suspiciousUrls');
const emailsFlaggedElement = document.getElementById('emailsFlagged');
const phishingAlert = document.querySelector('.phishing-alert');
// QR code related elements
const qrCodesDetectedElement = document.getElementById('qrCodesDetected');
const qrMaliciousUrlsElement = document.getElementById('qrMaliciousUrls');
const qrAlert = document.querySelector('.qr-alert');

// Event Listeners
document.addEventListener('DOMContentLoaded', initializePopup);
loginButton.addEventListener('click', handleLogin);
scanButton.addEventListener('click', handleScan);

// Initialize popup
function initializePopup() {
    const token = localStorage.getItem('access_token');
    const tokenExpiry = localStorage.getItem('token_expiry');
    
    if (token && tokenExpiry && new Date(tokenExpiry) > new Date()) {
        // Token is valid
        updateUIForLoggedInState();
    } else {
        // Token is invalid or expired
        localStorage.removeItem('access_token');
        localStorage.removeItem('token_expiry');
        updateUIForLoggedOutState();
    }
}

// Auth Functions
async function handleLogin() {
    updateStatus('Authenticating...');
    
    try {
        // Try using chrome identity API first
        const token = await getAuthTokenWithIdentityAPI();
        handleSuccessfulAuth(token);
    } catch (error) {
        console.error('Authentication error with Identity API:', error);
        
        // Fall back to web auth flow
        try {
            const token = await getAuthTokenWithWebFlow();
            handleSuccessfulAuth(token);
        } catch (webFlowError) {
            console.error('Authentication error with Web Flow:', webFlowError);
            updateStatus('Authentication failed. Please try again.');
        }
    }
}

function getAuthTokenWithIdentityAPI() {
    return new Promise((resolve, reject) => {
        chrome.identity.getAuthToken({ interactive: true }, function(token) {
            if (chrome.runtime.lastError) {
                reject(chrome.runtime.lastError);
            } else if (token) {
                resolve(token);
            } else {
                reject(new Error('No token received'));
            }
        });
    });
}

function getAuthTokenWithWebFlow() {
    return new Promise((resolve, reject) => {
        // Encode the URL parameters
        const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authUrl.searchParams.append('client_id', CLIENT_ID);
        authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
        authUrl.searchParams.append('response_type', 'token');
        authUrl.searchParams.append('scope', SCOPES);
        authUrl.searchParams.append('include_granted_scopes', 'true');
        authUrl.searchParams.append('state', 'state_parameter_passthrough_value');
        
        chrome.identity.launchWebAuthFlow(
            {
                url: authUrl.toString(),
                interactive: true
            },
            function(responseUrl) {
                if (!responseUrl) {
                    reject(new Error('No response URL received'));
                    return;
                }
                
                try {
                    // Parse the access token from the URL fragment
                    const urlParams = new URLSearchParams(new URL(responseUrl).hash.substring(1));
                    const accessToken = urlParams.get('access_token');
                    const expiresIn = urlParams.get('expires_in');
                    
                    if (accessToken) {
                        resolve(accessToken);
                    } else {
                        reject(new Error('No access token in response'));
                    }
                } catch (error) {
                    reject(error);
                }
            }
        );
    });
}

function handleSuccessfulAuth(token) {
    // Calculate expiry (subtract 5 minutes to be safe)
    const expiryDate = new Date();
    expiryDate.setMinutes(expiryDate.getMinutes() + 55); // OAuth tokens typically last 1 hour
    
    // Store token and expiry
    localStorage.setItem('access_token', token);
    localStorage.setItem('token_expiry', expiryDate.toISOString());
    
    updateUIForLoggedInState();
    updateStatus('Authenticated! You can now scan your emails.');
}

// UI State Functions
function updateUIForLoggedInState() {
    loginButton.textContent = 'Re-authenticate';
    scanButton.disabled = false;
    daysSelect.disabled = false;
    maxEmailsInput.disabled = false;
}

function updateUIForLoggedOutState() {
    loginButton.textContent = 'Login with Google';
    scanButton.disabled = true;
    daysSelect.disabled = true;
    maxEmailsInput.disabled = true;
    resultsContainer.style.display = 'none';
    progressContainer.style.display = 'none';
}

function updateStatus(message) {
    statusText.textContent = message;
}

// Scan Functions
async function handleScan() {
    const token = localStorage.getItem('access_token');
    
    if (!token) {
        updateStatus('Please log in first!');
        return;
    }
    
    // Get scan options
    const days = daysSelect.value;
    const maxEmails = maxEmailsInput.value;
    
    // Update UI
    scanButton.disabled = true;
    updateStatus(`Scanning emails from the past ${days} days...`);
    progressContainer.style.display = 'block';
    progressBar.style.width = '10%';
    resultsContainer.style.display = 'none';
    phishingAlert.style.display = 'none';
    if (qrAlert) qrAlert.style.display = 'none';
    
    try {
        // Show scanning is in progress
        let progress = 10;
        const progressInterval = setInterval(() => {
            progress += 5;
            if (progress <= 90) {
                progressBar.style.width = `${progress}%`;
            }
        }, 500);
        
        // Make API request
        const response = await fetch(`${API_BASE_URL}/fetch_emails?days=${days}&max_emails=${maxEmails}`, {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });
        
        // Clear progress interval
        clearInterval(progressInterval);
        
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        
        const data = await response.json();
        progressBar.style.width = '100%';
        
        // Process and display results
        processResults(data);
    } catch (error) {
        console.error('Error:', error);
        updateStatus(`Error: ${error.message}`);
        progressBar.style.width = '0%';
    } finally {
        scanButton.disabled = false;
        // Hide progress bar after a delay
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 1000);
    }
}

function processResults(data) {
    // Check if there's an error
    if (data.error) {
        updateStatus(`Error: ${data.error}`);
        return;
    }
    
    // Display results
    resultsContainer.style.display = 'block';
    
    // Count total suspicious URLs and Safe Browsing detections
    let suspiciousUrlCount = 0;
    let safeBrowsingDetections = 0;
    
    // Add QR tracking
    let qrCodesDetected = 0;
    let qrMaliciousCount = 0;
    let qrSafeBrowsingDetections = 0;
    
    if (data.emails_data) {
        data.emails_data.forEach(email => {
            if (email.urls) {
                suspiciousUrlCount += email.malicious_urls || 0;
                safeBrowsingDetections += email.safe_browsing_detected || 0;
            }
            
            // Add QR code counting from individual emails
            qrCodesDetected += email.qr_codes_found || 0;
            qrMaliciousCount += email.qr_malicious_urls || 0;
            qrSafeBrowsingDetections += email.qr_safe_browsing_detected || 0;
        });
    }
    
    // Use summary counts if available (from server aggregation)
    if (data.qr_codes_detected !== undefined) {
        qrCodesDetected = data.qr_codes_detected;
    }
    
    if (data.qr_malicious_detected !== undefined) {
        qrMaliciousCount = data.qr_malicious_detected;
    }
    
    // Count phishing emails
    const phishingEmailCount = data.emails_data ? 
        data.emails_data.filter(email => email.moved_to_label).length : 0;
    
    // Update statistics
    emailsScannedElement.textContent = data.emails_checked || 0;
    suspiciousUrlsElement.textContent = suspiciousUrlCount;
    emailsFlaggedElement.textContent = phishingEmailCount;
    
    // Update QR statistics if elements exist
    if (qrCodesDetectedElement) {
        qrCodesDetectedElement.textContent = qrCodesDetected;
    }
    
    if (qrMaliciousUrlsElement) {
        qrMaliciousUrlsElement.textContent = qrMaliciousCount;
    }
    
    // Show/hide QR stats based on detection
    const qrStatsElements = document.querySelectorAll('.qr-stats');
    qrStatsElements.forEach(el => {
        el.style.display = qrCodesDetected > 0 ? 'flex' : 'none';
    });
    
    // Check if safeBrowsingsElement exists before trying to use it
    const safeBrowsingsElement = document.getElementById('safeBrowsings');
    if (safeBrowsingsElement) {
        safeBrowsingsElement.textContent = safeBrowsingDetections;
        const safeBrowsingStatElement = document.querySelector('.safe-browsing-stat');
        if (safeBrowsingStatElement) {
            safeBrowsingStatElement.style.display = 
                safeBrowsingDetections > 0 ? 'flex' : 'none';
        }
    }
    
    // Show phishing alert if needed
    if (phishingEmailCount > 0) {
        phishingAlert.style.display = 'block';
        phishingAlert.innerHTML = `<strong>Phishing emails detected!</strong> ${phishingEmailCount} suspicious emails have been moved to your "Phishing" label in Gmail.`;
        
        // Add Safe Browsing info if available
        if (safeBrowsingDetections > 0) {
            phishingAlert.innerHTML += ` <span class="safe-browsing-badge">${safeBrowsingDetections} URLs confirmed by Google Safe Browsing</span>`;
        }
    } else {
        phishingAlert.style.display = 'none';
    }
    
    // Show QR alert if needed
    if (qrMaliciousCount > 0 && qrAlert) {
        qrAlert.style.display = 'block';
        qrAlert.innerHTML = `<strong><span class="qr-icon">QR</span>Malicious QR codes detected!</strong> ${qrMaliciousCount} URLs from QR codes were identified as malicious.`;
        
        // Add Safe Browsing info for QR codes if available
        if (qrSafeBrowsingDetections > 0) {
            qrAlert.innerHTML += ` <span class="safe-browsing-badge">${qrSafeBrowsingDetections} confirmed by Google Safe Browsing</span>`;
        }
    } else if (qrAlert) {
        qrAlert.style.display = 'none';
    }
    
    // Update status text
    const timeRange = data.time_range || `Last ${daysSelect.value} days`;
    updateStatus(`Scan complete! ${timeRange}`);
    
    // Show notification
    showNotification(data.emails_checked, phishingEmailCount, safeBrowsingDetections, qrMaliciousCount);
}

function showNotification(emailsChecked, phishingCount, safeBrowsingCount = 0, qrMaliciousCount = 0) {
    let message = phishingCount > 0 
        ? `Scanned ${emailsChecked} emails. Found and moved ${phishingCount} phishing emails!` 
        : `Scanned ${emailsChecked} emails. No phishing emails found.`;
        
    // Add Safe Browsing info to notification if available
    if (safeBrowsingCount > 0) {
        message += ` (${safeBrowsingCount} confirmed by Web Risk API)`;
    }
    
    // Add QR code info to notification if available
    if (qrMaliciousCount > 0) {
        message += ` Found ${qrMaliciousCount} malicious QR codes!`;
    }
    
    chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "Gmail Scan Complete",
        message: message
    });
}