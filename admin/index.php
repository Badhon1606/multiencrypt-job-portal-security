<?php
session_start();

// 1. If ALREADY logged in as Admin, send to Dashboard
// We check if the session is set. If yes, we skip login and go straight to dashboard.
if(isset($_SESSION['id_admin']) && isset($_SESSION['role']) && $_SESSION['role'] == 'admin') {
    header("Location: dashboard.php");
    exit();
}

// 2. If logged in as Candidate/Company, redirect to their dashboards (Optional but good UX)
if(isset($_SESSION['id_user'])) {
    header("Location: ../user/index.php");
    exit();
}
if(isset($_SESSION['id_company'])) {
    header("Location: ../company/index.php");
    exit();
}
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Job Portal | Admin Login</title>
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
  <link rel="stylesheet" href="../css/AdminLTE.min.css">
  <link rel="stylesheet" href="../css/_all-skins.min.css">

  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700,300italic,400italic,600italic">
</head>
<body class="hold-transition login-page">
<div class="login-box">
  <div class="login-logo">
    <a href="../index.php"><b>Job</b> Portal</a>
  </div>
  <div class="login-box-body">
    <p class="login-box-msg">Admin Login</p>

    <form action="checklogin.php" method="post">
      <div class="form-group has-feedback">
        <input type="text" name="username" class="form-control" placeholder="Username" required>
        <span class="glyphicon glyphicon-envelope form-control-feedback"></span>
      </div>
      <div class="form-group has-feedback">
        <input type="password" name="password" class="form-control" placeholder="Password" required>
        <span class="glyphicon glyphicon-lock form-control-feedback"></span>
      </div>
      <div class="row">
        <div class="col-xs-4">
          <button type="submit" class="btn btn-primary btn-block btn-flat">Sign In</button>
        </div>
        </div>
      <?php 
      if(isset($_SESSION['loginError'])) {
        ?>
        <div>
          <p class="text-center" style="color: red;">Invalid Username or Password!</p>
        </div>
      <?php
       unset($_SESSION['loginError']); }
      ?>

    </form>
  </div>
  </div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
<script src="../js/adminlte.min.js"></script>

</body>
</html>