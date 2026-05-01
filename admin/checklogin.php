<?php
session_start();
require_once("../db.php");

if(isset($_POST)) {

    $username = mysqli_real_escape_string($conn, $_POST['username']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);

    // 1. Fetch Admin Data (Make sure 'email' column exists in your admin table!)
    $sql = "SELECT * FROM admin WHERE username='$username'";
    $result = $conn->query($sql);

    if($result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            
            // 2. Verify Password
            if(password_verify($password, $row['password'])) {

                // 3. Secure Session & 2FA Setup
                session_regenerate_id(true);

                // Generate OTP
                $otp = rand(100000, 999999);
                
                // Store Temporary Session Vars
                $_SESSION['temp_id_admin'] = $row['id_admin'];
                $_SESSION['temp_role'] = 'admin'; 
                
                // IMPORTANT: Hash the OTP to match verify.php logic
                $_SESSION['otp'] = password_hash($otp, PASSWORD_DEFAULT); 
                
                // ==========================================
                // SEND OTP EMAIL
                // ==========================================
                
                // Check if email exists in DB row. If not, fallback to a default or show error.
                $to = isset($row['email']) ? $row['email'] : 'britanialelouch10143@gmail.com'; 
                $subject = "Job Portal - Admin Login Verification";
                
                // HTML Email Body
                $message = "
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #d9534f; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
                        .content { background: #f9f9f9; padding: 30px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }
                        .otp-box { background: white; padding: 20px; text-align: center; border: 2px dashed #d9534f; margin: 20px 0; border-radius: 5px; }
                        .otp-code { font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #d9534f; }
                        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #777; border-top: 1px solid #ddd; padding-top: 20px; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <div class='header'>
                            <h1 style='margin: 0;'>Admin Portal</h1>
                            <p style='margin: 5px 0 0 0;'>Security Verification</p>
                        </div>
                        <div class='content'>
                            <p>Hello <strong>Admin</strong>,</p>
                            <p>A login attempt was detected for your Administrator account.</p>
                            
                            <div class='otp-box'>
                                <div class='otp-code'>$otp</div>
                            </div>
                            
                            <p><strong>Warning:</strong> Do not share this code with anyone.</p>
                        </div>
                        <div class='footer'>
                            <p>&copy; " . date('Y') . " Job Portal. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>";
                
                // Email Headers
                $headers = "MIME-Version: 1.0" . "\r\n";
                $headers .= "Content-type: text/html; charset=UTF-8" . "\r\n";
                $headers .= "From: Job Portal Admin <admin@jobportal.com>" . "\r\n"; 
                
                // Send Email
                if(mail($to, $subject, $message, $headers)) {
                    header("Location: ../verify.php"); 
                    exit();
                } else {
                    // Fallback if mail fails (usually in local env)
                    // For now, redirect anyway so you can check XAMPP mailoutput
                    header("Location: ../verify.php"); 
                    exit();
                }

            } else {
                // Password Wrong
                $_SESSION['loginError'] = true;
                header("Location: index.php");
                exit();
            }
        }
    } else {
        // Username Wrong
        $_SESSION['loginError'] = true;
        header("Location: index.php");
        exit();
    }

    $conn->close();

} else {
    header("Location: index.php");
    exit();
}
?>