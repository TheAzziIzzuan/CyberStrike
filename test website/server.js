const express = require("express");
const app = express();
const path = require("path");

// Serve static files (like index.html)
app.use(express.static(path.join(__dirname)));

// ✅ Fix: Create an /admin page
app.get("/admin", (req, res) => {
    res.send("<h1>🔒 Admin Panel</h1><p>This page should be restricted, but it's accessible!</p>");
});

// ✅ Fix: Simulate a restricted page
app.get("/restricted", (req, res) => {
    res.status(403).send("<h1>⛔ Access Denied (403)</h1><p>You are not authorized to view this page.</p>");
});

// ✅ Fix: Simulate an exposed API endpoint
app.get("/api/public-data", (req, res) => {
    res.json({ message: "🚨 This API is publicly accessible!", status: "unprotected" });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Test site running at http://localhost:${PORT}`);
});
