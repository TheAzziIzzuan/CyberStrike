<?php
if (!isset($_COOKIE['username'])) {
    header("Location: login.html");
    exit();
}

setcookie("secret", base64_encode("extremelysecretivesecret"), time()+3600, "/", "", false, false)
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Main Page</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<!-- Include the NAVBAR -->
<?php include 'navbar.php'; ?>


<!-- Main Content Container -->
<div class="container">
    <h1>Welcome to the Main Page</h1>
    <p>This is your dashboard.</p>
</div>

</body>
</html>
