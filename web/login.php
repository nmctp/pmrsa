<?php
session_start();
if (isset($_SESSION['user'])) {
        header("Location: index.php");
        exit;
        }

$fname = tempnam("/tmp", "pmr");
while(!$fname || strlen(basename($fname)) > 10)
                $fname = tempnam("/tmp", "pmr");
$chall = rand(1000000000,9999999999);
file_put_contents($fname, "$chall");
if(($i = 10 - strlen(basename($fname)))>0)
        $fname .= str_repeat('-', $i);

// this magic name should be configurable
$modulus = file_get_contents("pmrsa_key.mod");
$exp     = file_get_contents("pmrsa_key.exp");

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/ 
xhtml1/DTD/xhtml1-transitional.dtd"> 
<html> 
<head>
<meta base="http://pfortuny.net/" />
<title>Poor Man's RSA Test</title> 
<script src="/pmrsa/pmrsa.js" type="text/javascript"></script>
<script src="/pmrsa/jsbn.js" type="text/javascript"></script>
<script src="/pmrsa/jsbn2.js" type="text/javascript"></script>
<script src="/pmrsa/prng4.js" type="text/javascript"></script>
<script src="/pmrsa/rng.js" type="text/javascript"></script>
<script src="/pmrsa/rsa.js" type="text/javascript"></script>
<script src="/pmrsa/rsa2.js" type="text/javascript"></script>

<link rel='stylesheet' href='/pmrsa/css/pmrsa.css' type='text/css' media='all' />

</head>
<!-- For best random results -->
<body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
<input type="hidden" name="tempfile" value="<?php  print basename($fname); ?>" />
<input type="hidden" name="challenge" value="<?php print $chall; ?>" />
<input type="hidden" name="publickey" value="<?php print $modulus; ?>" />
<!-- hex exponent -->
<input type="hidden" name="exponent" value="<?php print $exp; ?>" />

<div id="login">
<h2>Poor Man's RSA Concept Test</h2>
<p class="message">Try 'admin', 'passw0rd' to enter</p>
<form name="loginform" id="loginform" method="post">
  <p>
    <label>Username<br />
      <input type="text" name="user" id="user_login" class="input" value="" size="20" tabindex="10" />
    </label>
  </p>
  <p>
    <label>Password<br />
      <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" tabindex="20" />
    </label>
  </p>
  <p class="submit">
    <input type="button" value="Log In" tabindex="100" onclick="safe_login()" />
  </p>
</form>
</div>

<div id="login_error">
</div>

<!--only used in demos -->
<!-- <div class="message"> -->
<!-- <p>Encrypted password: </p> -->
<!-- <textarea cols="20" rows="4" id="encrypted_pass" type="text" readonly=true></textarea> -->
<!-- </div> -->

<!-- <div class="message">Password (AJAX received): <span class="answer" id="pass"></span></div> -->
<!-- <div class="message">Filename (ibid): <span class="answer" id="filename"></span></div> -->
<!-- <div class="message">Challenge (ibid): <span class="answer" id="challenge"></span></div> -->


</body> 
</html>

