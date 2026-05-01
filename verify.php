<?php
session_start();

if(empty($_SESSION['otp'])) {
    header("Location: index.php");
    exit();
}

if(isset($_POST['submit_otp'])) {
    
    $user_otp = $_POST['otp_code'];
    $stored_hash = $_SESSION['otp'];

    // --- SECURITY FIX: Use password_verify ---
    if(password_verify($user_otp, $stored_hash)) {
        
        // --- SUCCESS ---
        
        if($_SESSION['temp_role'] == 'candidate') {
            $_SESSION['id_user'] = $_SESSION['temp_id_user'];
            $_SESSION['name'] = $_SESSION['temp_name'];
            $_SESSION['role'] = 'candidate';
            $redirect = "user/index.php";

        } else if ($_SESSION['temp_role'] == 'company') {
            $_SESSION['id_company'] = $_SESSION['temp_id_company'];
            $_SESSION['name'] = $_SESSION['temp_name'];
            $_SESSION['role'] = 'company';
            $redirect = "company/index.php";

        } else if ($_SESSION['temp_role'] == 'admin') {
            $_SESSION['id_admin'] = $_SESSION['temp_id_admin'];
            $_SESSION['role'] = 'admin';
            $redirect = "admin/dashboard.php";
        }

        // Clear temp session
        unset($_SESSION['otp']);
        unset($_SESSION['temp_id_user']);
        unset($_SESSION['temp_id_company']);
        unset($_SESSION['temp_id_admin']);
        unset($_SESSION['temp_role']);
        unset($_SESSION['temp_name']);

        header("Location: " . $redirect);
        exit();

    } else {
        $error = "Invalid OTP! Please try again.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Job Portal | Verify Login</title>
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css">
  <link rel="stylesheet" href="css/AdminLTE.min.css">
  <link rel="stylesheet" href="css/_all-skins.min.css">
</head>
<body class="hold-transition login-page">
<div class="login-box">
  <div class="login-logo">
    <a href="index.php"><b>Job</b> Portal</a>
  </div>
  
  <div class="login-box-body">
    <p class="login-box-msg">Two-Step Verification</p>

    <form method="post" action="">
      <div class="form-group has-feedback">
        <input type="number" name="otp_code" class="form-control" placeholder="Enter 6-digit OTP" required>
        <span class="glyphicon glyphicon-lock form-control-feedback"></span>
      </div>
      
      <?php if(isset($error)) { ?>
          <p style="color:red; text-align: center;"><?php echo $error; ?></p>
      <?php } ?>

      <div class="row">
        <div class="col-xs-12">
          <button type="submit" name="submit_otp" class="btn btn-primary btn-block btn-flat">Verify & Login</button>
        </div>
      </div>
    </form>
    
    <br>
    <div class="text-center">
        <a href="logout.php">Cancel Login</a>
    </div>

  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
</body>
</html>