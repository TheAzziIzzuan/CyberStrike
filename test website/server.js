const express = require("express");
const app = express();
const path = require("path");
const axios = require("axios");

// ✅ Serve static files (like index.html)
app.use(express.static(path.join(__dirname)));

// ✅ Serve `index.html` and inject SSRF script dynamically
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// ✅ Serve inline JavaScript for SSRF Test
app.get("/ssrf-script.js", (req, res) => {
    res.setHeader("Content-Type", "application/javascript");
    res.send(`
        document.addEventListener("DOMContentLoaded", () => {
            const ssrfTestButton = document.getElementById("ssrfTestButton");
            const ssrfResponse = document.getElementById("ssrfResponse");

            if (ssrfTestButton) {
                ssrfTestButton.addEventListener("click", async () => {
                    ssrfResponse.innerText = "🕵️ Fetching internal data...";
                    try {
                        let response = await fetch("http://127.0.0.1:8080/private-api");
                        let data = await response.text();
                        ssrfResponse.innerHTML = \`🔴 SSRF Response: <pre>\${data}</pre>\`;
                    } catch (error) {
                        ssrfResponse.innerText = "✅ SSRF request failed (internal server not reachable).";
                    }
                });
            }
        });
    `);
});

// ✅ Simulated Admin Panel (Exposed Page)
app.get("/admin", (req, res) => {
    res.send("<h1>🔒 Admin Panel</h1><p>This page should be restricted, but it's accessible!</p>");
});

// ✅ Simulated Restricted Page (403 Forbidden)
app.get("/restricted", (req, res) => {
    res.status(403).send("<h1>⛔ Access Denied (403)</h1><p>You are not authorized to view this page.</p>");
});

// ✅ Simulated Open API Endpoint (Exposed)
app.get("/api/public-data", (req, res) => {
    res.json({ message: "🚨 This API is publicly accessible!", status: "unprotected" });
});

// ✅ Simulated Internal SSRF Vulnerability
app.get("/ssrf-test", async (req, res) => {
    try {
        let response = await axios.get("http://127.0.0.1:8080/private-api");
        res.send(`Internal API Response: ${response.data}`);
    } catch (error) {
        res.send("❌ Failed to reach internal API.");
    }
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Test site running at http://localhost:${PORT}`);
});
