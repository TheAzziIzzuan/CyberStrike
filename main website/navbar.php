<nav class="navbar">
    <ul>
        <li><a href="mainpage.php">Home</a></li>

        <?php
        // If user is logged in, show Profile link with ID
        if (isset($_COOKIE['username']) && isset($_COOKIE['id'])) {
            echo '<li><a href="profile.php?id=' . $_COOKIE['id'] . '">Profile</a></li>';
        } else {
            // If not logged in, show a "Login" link
            echo '<li><a href="login.html">Login</a></li>';
        }

        // Admin-only link
        if (isset($_COOKIE['role']) && $_COOKIE['role'] === 'admin') {
            echo '<li><a href="view_users.php">View Users</a></li>';
        }
        ?>

        <li><a href="logout.php">Logout</a></li>
    </ul>
</nav>
