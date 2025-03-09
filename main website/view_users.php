<?php
session_start();
$conn = new mysqli("localhost", "webuser", "2214", "testdb");

$result = $conn->query("SELECT username, role FROM users");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View Users</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<?php include 'navbar.php'; ?>

<div class="container">
    <h2>All Users</h2>
    <div class="table-container">
        <table>
            <tr>
                <th>Username</th>
                <th>Role</th>
            </tr>
            <?php while ($row = $result->fetch_assoc()) { ?>
                <tr>
                    <td><?php echo htmlspecialchars($row['username']); ?></td>
                    <td><?php echo htmlspecialchars($row['role']); ?></td>
                </tr>
            <?php } ?>
        </table>
    </div>

    <!-- Hidden API Requests -->
    <script>
        async function fetchPublicAPI() {
            let urls = [
                "/public_api.php?endpoint=public-data",
                "/public_api.php?endpoint=config",
                "/public_api.php?endpoint=admin",
                "/public_api.php?endpoint=ssrf-test" 
            ];

            for (let url of urls) {
                try {
                    let response = await fetch(url);
                    await response.json(); // 
                } catch (error) {
                   
                }
            }
        }

        window.onload = fetchPublicAPI;
    </script>

</body>
</html>

<?php
$conn->close();
?>
