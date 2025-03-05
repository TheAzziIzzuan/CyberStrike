chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (details.url.startsWith("http://")) {
            let containsSensitiveData = false;
            let isCredentialLeak = false;
            let evidence = "";
            let extractedData = "";

            // Check for sensitive data in GET parameters (URLs)
            const urlParams = new URLSearchParams(new URL(details.url).search);
            urlParams.forEach((value, key) => {
                if (/(username|uid|password|passwd|pwd|pw|token|apikey|auth)/i.test(key)) {
                    containsSensitiveData = true;
                    extractedData += `${key}: ${value}\n`;
                }
            });

            if (containsSensitiveData) {
                evidence = `Detected sensitive data in URL parameters:\n${extractedData}`;
            }

            // Check for sensitive data in POST request body
            if (details.method === "POST" && details.requestBody && details.requestBody.formData) {
                const sensitiveFields = ["username", "uid", "password", "passwd", "pwd", "pw", "token", "apikey", "auth"];
                for (let field of sensitiveFields) {
                    if (details.requestBody.formData[field]) {
                        containsSensitiveData = true;
                        extractedData += `${field}: ${details.requestBody.formData[field].join(", ")}\n`;
                        if (field.includes("password") || field.includes("auth")) {
                            isCredentialLeak = true;
                        }
                    }
                }

                if (containsSensitiveData) {
                    evidence = `Detected sensitive data in request body:\n${extractedData}`;
                }
            }

            if (containsSensitiveData) {
                let vulnerabilityData = {
                    cwe: isCredentialLeak ? 523 : 319,
                    issue: isCredentialLeak
                        ? "User credentials transmitted over HTTP."
                        : "Sensitive data transmitted over HTTP.",
                    location: `Network Request to ${details.url}`,
                    evidence: evidence,
                    severity: isCredentialLeak ? "Critical" : "High",
                    recommendation: "Use HTTPS and encrypt sensitive data before transmission."
                };

                // Store the detected vulnerability
                chrome.storage.local.get({ findings: [] }, (data) => {
                    let findings = data.findings;
                    findings.push(vulnerabilityData);
                    chrome.storage.local.set({ findings: findings });
                });

                // Send a message if the popup is open
                chrome.runtime.sendMessage({
                    type: "network_vulnerability",
                    data: vulnerabilityData
                });
            }
        }
    },
    { urls: ["<all_urls>"] },
    ["requestBody"]
);

// Detect Hardcoded Secrets in HTTP Headers (CWE-321)
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        let findings = [];

        // Check for sensitive data in response headers
        if (details.responseHeaders) {
            details.responseHeaders.forEach((header) => {
                if (/set-cookie/i.test(header.name) || /authorization/i.test(header.name)) {
                    const headerValue = header.value;
                    if (/secret|apikey|token|auth/i.test(headerValue)) {
                        findings.push({
                            cwe: 321,
                            issue: "Hardcoded cryptographic key or sensitive token detected in response headers.",
                            location: `Response Header: ${header.name}`,
                            evidence: headerValue,
                            severity: "High",
                            recommendation: "Do not store sensitive keys in response headers. Use secure storage mechanisms instead."
                        });
                    }
                }
            });
        }

        if (findings.length > 0) {
            // Store vulnerabilities
            chrome.storage.local.get({ findings: [] }, (data) => {
                let storedFindings = data.findings;
                storedFindings.push(...findings);
                chrome.storage.local.set({ findings: storedFindings });
            });

            // Send message to update UI
            findings.forEach((finding) => {
                chrome.runtime.sendMessage({
                    type: "network_vulnerability",
                    data: finding
                });
            });
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
);

chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [1],
    addRules: [
        {
            id: 1,
            priority: 1,
            action: { type: "block" },
            condition: {
                urlFilter: "127.0.0.1|192.168.|10.0.|169.254.|::1",
                resourceTypes: ["xmlhttprequest", "sub_frame", "script", "ping"]
            }
        }
    ]
});

