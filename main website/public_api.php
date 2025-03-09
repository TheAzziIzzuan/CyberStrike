<?php
header('Content-Type: application/json');

// Define the simulated API endpoints
$endpoints = [
    "public-data" => [
        "user" => "test_user",
        "email" => "test@example.com",
        "api_key" => "12345-ABCDE"
    ],
    "config" => [
        "db_host" => "localhost",
        "db_user" => "root",
        "db_password" => "rootpassword"
    ],
    "admin" => [
        "username" => "admin",
        "password" => "admin123"
    ]
];

// Get the requested endpoint from the URL
$requested_endpoint = $_GET['endpoint'] ?? null;

// Check if the endpoint exists
if (isset($endpoints[$requested_endpoint])) {
    echo json_encode($endpoints[$requested_endpoint], JSON_PRETTY_PRINT);
} else {
    http_response_code(404);
    echo json_encode(["error" => "Endpoint not found"]);
}
?>
