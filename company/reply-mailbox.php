<?php

// 1. Start Session
session_start();

// 2. Include Database
require_once("../db.php");


if(empty($_SESSION['id_company']) || $_SESSION['role'] != 'company') {
    header("Location: ../index.php");
    exit();
}

// 4. Handle the POST request
if(isset($_POST)) {
    
    // 5. SECURITY: Escape ALL inputs (Prevent SQL Injection)
    // You missed escaping 'id_mail' in your original code!
    $id_mail = mysqli_real_escape_string($conn, $_POST['id_mail']);
    $message = mysqli_real_escape_string($conn, $_POST['description']);
    $id_company = $_SESSION['id_company']; // Use the session variable we verified above

    // 6. Insert Query
    // Notice we use the variables we just cleaned ($id_mail, $id_company), not the raw $_POST arrays
    $sql = "INSERT INTO reply_mailbox (id_mailbox, id_user, usertype, message) VALUES ('$id_mail', '$id_company', 'company', '$message')";

    if($conn->query($sql) == TRUE) {
        header("Location: read-mail.php?id_mail=".$id_mail);
        exit();
    } else {
        echo $conn->error;
    }
} else {
    header("Location: mailbox.php");
    exit();
}
?>