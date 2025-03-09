<?php
$conn = new mysqli("localhost", "webuser", "2214", "testdb");

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// If ?id is missing, user sees "No user ID specified."
if (!isset($_GET['id'])) {
    header("HTTP/1.1 404 Not Found");
    exit();
}

$id = $_GET['id'];

$query = "SELECT * FROM users WHERE id = $id";
$result = $conn->query($query);

if ($result && $result->num_rows > 0) {
    $user = $result->fetch_assoc();
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>User Profile</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <!-- Include the NAVBAR -->
        <?php include 'navbar.php'; ?>
        
        <div class="container">
            <h1>User Profile</h1>
            <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
            <p><strong>Role:</strong> <?php echo htmlspecialchars($user['role']); ?></p>

            <!-- Add the invoice download link -->
            <h3>Your Invoice</h3>
            <?php
            // Generate the invoice filename based on the user ID
            $invoice_file = "invoice_" . $user['id'] . ".pdf";
            // Display the download link for the invoice
            echo "<a href='download.php?file=$invoice_file'>Download Your Invoice</a>";
            ?>
        </div>
    </body>
    </html>
    <?php
} else {
    header("HTTP/1.1 404 Not Found");
    exit();
}
$conn->close();
?>
