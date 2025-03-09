<?php
$conn = new mysqli("localhost", "webuser", "2214", "testdb");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get user input directly (Vulnerable to SQL Injection)
$username = $_GET['username'];
$password = $_GET['password'];

// Construct a vulnerable SQL query (without prepared statements)
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($query);

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();

    // Store user cookie
    setcookie("id", $user['id'], time() + (86400 * 30), "/");
    setcookie("username", $user['username'], time() + (86400 * 30), "/");
    setcookie("role", $user['role'], time() + (86400 * 30), "/");

    // Redirect to main page
    header("Location: mainpage.php");
    exit();
} else {
    echo "Invalid credentials! Redirecting...";
    header("refresh:3; url=login.html"); // Redirect to login page after 3 seconds
}

$conn->close();
?>