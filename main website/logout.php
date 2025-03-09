<?php
setcookie("id", "", time() - 3600, "/");
setcookie("username", "", time() - 3600, "/");
setcookie("role", "", time() - 3600, "/");

header("Location: login.html");
exit();
?>