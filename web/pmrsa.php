<?php

require('pmrsa-config.php');
require('your_app.php');

$cyp_key = $_POST['pass'];

if(strlen($cyp_key) > 0){
        $user = $_POST['user'];

        $kill_dashes = "/[\-]+/";
        $tempfile = preg_replace($kill_dashes, "", $_POST['tempfile']);
        $tempfile = sys_get_temp_dir() . '/' . $tempfile;

        // this magical 10 (the challenge length) should change somehow,
        // but it may as well remain
        if (strlen($local_challenge = file_get_contents($tempfile))!= 10){
                unlink($tempfile);
                echo(json_encode(array("YOU" => "blew it")));
                exit;
        }

        $cmd = "/home2/pfortuny/public_html/pmrsa/pm_rsa_server -k /home2/pfortuny/public_html/pmrsa/rsa1.2048 $cyp_key";
        $cmd_esc = escapeshellcmd($cmd);
        $last_line = exec($cmd_esc);

        // challenge, filename (discarded), password
        $fields = "/^(.*?);(.*?);(.*)$/";
        preg_match_all($fields, $last_line, $matches);

        // Warning: $matches[i] is an array
        $challenge = $matches[1][0];
        if($local_challenge != $challenge){
                unlink($tempfile); //serves you well
                echo(json_encode(array("YOU" => "blew it")));
                exit;
        }

        $password  = $matches[3][0];

        $valid_user = user_authentication($user, $password);
	if ( $valid_user == true) {
		$pmrsa_response['valid_user'] = 1;
                unlink($tempfile);
	} else {
		$pmrsa_response['valid_user'] = 0;
                // NO UNLINKING DONE because no reload
                // So we need to keep the challenge file
	}
	echo json_encode($pmrsa_response);

} else {
        echo json_encode(array('hi' => 'is there anybody out there?'));
}
?>

