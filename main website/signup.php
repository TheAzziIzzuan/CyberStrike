<?php
// Connect to the database
$conn = new mysqli("localhost", "webuser", "2214", "testdb");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Only process if form is submitted via GET
if ($_SERVER["REQUEST_METHOD"] === "GET") {
    // Retrieve user input from GET
    $username = $_GET['username'];
    $password = $_GET['password'];

    // Construct an INSERT query (vulnerable to SQL injection for testing)
    $query = "INSERT INTO users (username, password, role) VALUES ('$username', '$password', 'user')";

    if ($conn->query($query) === TRUE) {
        echo "User registered successfully! Redirecting to login page...";
        // Wait 3 seconds, then go to login.html
        header("refresh:3; url=login.html");
        exit();
    } else {
        // Show SQL error
        echo "Error: " . $query . "<br>" . $conn->error;
    }
} else {
    // If the user visits signup.php directly without GET data
    echo "Please submit the form via signup.html.";
}

$conn->close();
?>
