<?php
// Check if the user is logged in using cookies
if (!isset($_COOKIE['username'])) {
    die("Access denied. Please log in.");
}

// Get the 'file' parameter from the URL
if (isset($_GET['file'])) {
    $file = $_GET['file'];  // Get the invoice filename

    // Define the directory where invoices are stored
    $invoice_directory = "invoices/";

    // Create the full path to the file
    $file_path = $invoice_directory . $file;

    // Check if the file exists
    if (file_exists($file_path)) {
        // Force the browser to download the file
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($file_path));

        // Read the file and send it to the browser
        readfile($file_path);
        exit;
    } else {
        header("HTTP/1.1 404 Not Found");
        exit();
    }
} else {
    header("HTTP/1.1 404 Not Found");
    exit();
}
?>
