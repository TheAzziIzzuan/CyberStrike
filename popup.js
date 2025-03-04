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

  const outputDiv = document.getElementById("websiteOutput");
  outputDiv.innerHTML = "🔍 Scanning...";

  try {
      const response = await fetch(`http://ip-api.com/json/${url.hostname}`);
      const data = await response.json();

      if (data.status === "success") {
          outputDiv.innerHTML = `
               🌐 IP:  ${data.query}
🏙️ City:  ${data.city || "Not available"}
🗺️ Region:  ${data.regionName || "Not available"}
🇺🇸 Country:  ${data.country || "Not available"}
💻 ISP:  ${data.isp || "Not available"}

          `;
      } else {
          outputDiv.innerHTML = "❌ Failed to fetch server information.";
      }
  } catch (error) {
      outputDiv.innerHTML = "❌ Error occurred while fetching data.";
  }
});

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
    if (scanInProgress) return; // Prevent starting a new scan if one is already in progress

    // Reset UI
    resetOutput();
    await scanTxtFiles(); // Scan for .txt files
});

// Helper function to reset output and progress indicators
function resetOutput() {
    const outputDiv = document.getElementById("hiddenUrlsOutput");
    const progressText = document.getElementById("progressText");
    const foundCount = document.getElementById("foundCount");

    // Clear output and reset progress text
    outputDiv.innerHTML = ""; // Clear previous results
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

  // Reset variables
  let scannedUrls = 0;
  let foundUrlsCount = 0;
  let scannedPaths = new Set(); // Set to track unique URLs (case-sensitive)

  // Show Stop and hide Scan button
  document.getElementById("stopScanButton").style.display = "inline-block";
  document.getElementById("hiddenUrlsButton").style.display = "none";
  document.getElementById("scanTxtButton").style.display = "none";
  
  // Initialize scan state
  scanInProgress = true;
  scanAbortController = new AbortController();
  const signal = scanAbortController.signal;

  try {
      for (let path of commonUrls) {
          if (!scanInProgress) break;  // Stop if scan is no longer in progress

          // Check for duplicates (case sensitive)
          if (scannedPaths.has(path)) {
              continue; // Skip if already scanned
          }

          scannedPaths.add(path); // Add the path to the set

          try {
              // Check for hidden URL (no .txt extension)
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

          // Update Progress
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
      document.getElementById("hiddenUrlsButton").style.display = "inline-block";
      document.getElementById("scanTxtButton").style.display = "inline-block";
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

  // Load the wordlist
  const commonUrls = await loadWordlist();
  const totalUrls = commonUrls.length;

  // Reset variables
  let scannedUrls = 0;
  let foundTxtFilesCount = 0;
  let scannedPaths = new Set(); // Set to track unique URLs (case-sensitive)

  // Show Stop and hide Scan button
  document.getElementById("stopScanButton").style.display = "inline-block";
  document.getElementById("hiddenUrlsButton").style.display = "none";
  document.getElementById("scanTxtButton").style.display = "none";
  
  // Initialize scan state
  scanInProgress = true;
  scanAbortController = new AbortController();
  const signal = scanAbortController.signal;

  try {
      for (let path of commonUrls) {
          if (!scanInProgress) break;  // Stop if scan is no longer in progress

          let txtUrl = `${baseURL}/${path}.txt`;

          try {
              let txtRes = await fetch(txtUrl, { signal });

              if (txtRes.status === 200) {
                  outputDiv.innerHTML += `✅ Found .txt: <a href="${txtUrl}" target="_blank">${txtUrl}</a><br>`;
                  foundTxtFilesCount++;
              } else {
                  console.log(`Not found: ${txtUrl}`);  // Log if the file is not found
              }

          } catch (error) {
              if (error.name === 'AbortError') {
                  console.log("Scan was aborted.");
                  break;
              }
              console.warn(`❌ Error checking ${path}: ${error}`);
          }

          // Update Progress
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
      document.getElementById("hiddenUrlsButton").style.display = "inline-block";
      document.getElementById("scanTxtButton").style.display = "inline-block";
      scanInProgress = false;
  }
}

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







// Stop Scan Functionality for both types of scans
document.getElementById("stopScanButton").addEventListener("click", () => {
    if (scanAbortController) {
        scanAbortController.abort(); // Trigger the abort signal
    }

    // Update UI to reflect stopped scan
    document.getElementById("hiddenUrlsOutput").innerHTML = "❌ Scan Stopped.";
    document.getElementById("stopScanButton").style.display = "none"; // Hide Stop Button
    document.getElementById("hiddenUrlsButton").style.display = "inline-block"; // Show Scan Button
    document.getElementById("scanTxtButton").style.display = "inline-block"; // Show Scan Button
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
        removeFileButton.style.display = "inline-block"; // Show the Remove File button
    } else {
        fileNameDisplay.textContent = "";
        removeFileButton.style.display = "none"; // Hide the Remove File button
    }
});

// Remove File Button Functionality
removeFileButton.addEventListener("click", () => {
    fileInput.value = ""; // Clear the file input
    fileNameDisplay.textContent = ""; // Clear the displayed file name
    removeFileButton.style.display = "none"; // Hide the Remove File button
});

// Numeric Iteration Scan Functionality
document.getElementById("numericScanButton").addEventListener("click", async () => {
    if (scanInProgress) return; // Prevent starting a new scan if one is already in progress

    // Reset UI
    resetOutput();

    // Get user inputs
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

    // Show Stop and hide Scan button
    document.getElementById("stopScanButton").style.display = "inline-block";
    document.getElementById("numericScanButton").style.display = "none";
    
    // Initialize scan state
    scanInProgress = true;
    scanAbortController = new AbortController();
    const signal = scanAbortController.signal;

    try {
        for (let i = startNumber; i < startNumber + iterations; i++) {
            if (!scanInProgress) break;  // Stop if scan is no longer in progress

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

            // Update Progress
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
        document.getElementById("numericScanButton").style.display = "inline-block";
        scanInProgress = false;
    }
}