// background.js

// --- 1) Detect Sensitive Data or Credentials Sent Over HTTP (CWE-319 / CWE-523)

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      // Only look at HTTP (not HTTPS).
      if (details.url.startsWith("http://")) {
        let containsSensitiveData = false;
        let evidence = "";
        let extractedData = "";
  
        // We will track whether we think it's a "login" or "signup" request
        let isLoginRequest = false;
        let isSignUpRequest = false;
  
        // A broader set of keywords for login-like URLs:
        const loginKeywords = /login|signin|auth|authenticate|logon|session|token/i;
        // A broader set of keywords for sign-up/registration URLs:
        const signUpKeywords = /signup|register|createaccount|join|enroll|newuser|usercreate/i;
  
        // See if the URL path or query string matches either set of keywords
        const lowerUrl = details.url.toLowerCase();
        if (loginKeywords.test(lowerUrl)) {
          isLoginRequest = true;
        } else if (signUpKeywords.test(lowerUrl)) {
          isSignUpRequest = true;
        }
  
        // Typical credential parameter names to look for
        const credentialParamsRegex = /(username|uid|password|passwd|pwd|pw|token|apikey|auth)/i;
  
        // 1a) Check GET parameters
        const urlObj = new URL(details.url);
        const urlParams = new URLSearchParams(urlObj.search);
  
        urlParams.forEach((value, key) => {
          if (credentialParamsRegex.test(key)) {
            containsSensitiveData = true;
            extractedData += `${key}: ${value}\n`;
          }
        });
  
        // If we found anything in the GET params, note it
        if (containsSensitiveData) {
          evidence = `Detected sensitive data in URL parameters:\n${extractedData}`;
        }
  
        // 1b) Check POST parameters
        if (details.method === "POST" && details.requestBody && details.requestBody.formData) {
          const sensitiveFields = ["username","uid","password","passwd","pwd","pw","token","apikey","auth"];
          for (let field of sensitiveFields) {
            if (details.requestBody.formData[field]) {
              containsSensitiveData = true;
              extractedData += `${field}: ${details.requestBody.formData[field].join(", ")}\n`;
            }
          }
          if (containsSensitiveData) {
            evidence = `Detected sensitive data in POST body:\n${extractedData}`;
          }
        }
  
        // 1c) Decide which CWE to emit, if we have found user/pass
        if (containsSensitiveData) {
          // If we found user/pass AND it looks like a login page → 523
          // If it looks like a signup page → 319
          // Otherwise, default to 319
          let cwe;
          let issue;
          let severity;
  
          if (isLoginRequest) {
            cwe = 523;
            issue = "User credentials transmitted over HTTP (Login detected).";
            severity = "Critical";
          } else {
            // If specifically isSignUpRequest or unknown, treat as general cleartext sensitive data
            cwe = 319;
            issue = "Sensitive data transmitted over HTTP.";
            severity = "High";
          }
  
          chrome.runtime.sendMessage({
            type: "network_vulnerability",
            data: {
              cwe: cwe,
              issue: issue,
              location: `Network Request to ${details.url}`,
              evidence: evidence,
              severity: severity,
              recommendation: "Use HTTPS and encrypt sensitive data before transmission."
            }
          });
        }
      }
    },
    { urls: ["<all_urls>"] },
    ["requestBody"]
  );
  
  // --- 2) Detect Hardcoded Secrets in HTTP Headers (CWE-321)
  
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.responseHeaders) {
        details.responseHeaders.forEach((header) => {
          let headerValue = header.value || "";
  
          // If the header is Set-Cookie or Authorization, look for secret tokens
          if (/set-cookie/i.test(header.name) || /authorization/i.test(header.name)) {
            if (/secret|apikey|token|auth/i.test(headerValue)) {
              chrome.runtime.sendMessage({
                type: "network_vulnerability",
                data: {
                  cwe: 321,
                  issue: "Hardcoded cryptographic key or sensitive token detected in response headers.",
                  location: `Response Header: ${header.name}`,
                  evidence: headerValue,
                  severity: "High",
                  recommendation: "Do not store sensitive keys in response headers. Use secure storage mechanisms instead."
                }
              });
            }
          }
        });
      }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
  );
  
  // --- 3) SSRF Protection Rule
  
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
  
