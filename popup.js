// Handle Tab Switching
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

// General Scan Functionality
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

// Placeholder for Other Feature
document.getElementById("otherFeatureButton").addEventListener("click", () => {
  document.getElementById("otherFeatureOutput").innerHTML = "🔍 Running other security feature...";
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

// Functions to fetch additional data
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
