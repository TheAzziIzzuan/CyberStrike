<?php
session_start();


// Hardcoded admin credentials (VULNERABILITY)
$adminUsername = "admin";
$adminPassword = "admin123";

// Display admin details
echo "<h2>🔐 Admin Details</h2>";
echo "<p><strong>Username:</strong> $adminUsername</p>";
echo "<p><strong>Password:</strong> $adminPassword</p>";

// Simulated SSRF Vulnerability
if (isset($_GET['url'])) {
    $targetUrl = $_GET['url']; // ⚠️ Vulnerable input

    echo "<h2>🖥️ Attempting to Fetch URL...</h2>";
    echo "<p>Fetching: " . htmlspecialchars($targetUrl) . "</p>";

    // Fetch the requested URL (mimicking SSRF)
    $response = @file_get_contents($targetUrl);

    if ($response !== false) {
        echo "<h3>✅ Successfully fetched:</h3>";
        echo "<pre>" . htmlspecialchars($response) . "</pre>";
    } else {
        echo "<h3>❌ Failed to fetch URL.</h3>";
    }
    exit();
}

echo "<h2>⚠️ No external request made.</h2>";
?>
