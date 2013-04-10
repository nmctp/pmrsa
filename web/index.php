<?php
session_start();
if (!isset($_SESSION['user'])) {
	header("Location: login.php");
	exit;
} else { 
?>
<html>
<head>
<meta base="http://pfortuny.net/" />
<link rel='stylesheet' href='/pmrsa/css/pmrsa.css' type='text/css' media='all' />
<title>Your application main page</title>
</head>
<body>
<center id="login">
<div class="message">
Your are authenticated as <strong>
<?php
echo $_SESSION['user']; }
?>
</strong></br>
</div>
<a href="logout.php">Logout</a>
</center>
</body>
</html>
