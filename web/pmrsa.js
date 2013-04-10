var READY_STATE_COMPLETE=4;

var http_request = null;
var json_answer = "";

// standard XML-http-requests setup
function setup_xhr() {
    if(window.XMLHttpRequest) {
	return new XMLHttpRequest();
    }
    else if(window.ActiveXObject) {
	return new ActiveXObject("Microsoft.XMLHTTP");
    }
}

function safe_login() {
    http_request = setup_xhr();
    if(http_request) {
	http_request.onreadystatechange = send_login_items;
	http_request.open("POST", "http://pfortuny.net/pmrsa/pmrsa.php", true);
	http_request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	var username  = document.getElementById("user_login").value;
	var pass      = document.getElementById("user_pass");
	var pub_key   = document.getElementsByName("publickey")[0].value;
	var exponent  = document.getElementsByName("exponent")[0].value;
	var filename  = document.getElementsByName("tempfile")[0].value;
	var challenge = document.getElementsByName("challenge")[0].value;
	var plaintext = pass.value + challenge + filename + "\0";
	var rsa = new RSAKey();
	rsa.setPublic(pub_key, exponent);
	var cypher_pass = rsa.encrypt(plaintext);
	// used only in demos
	// document.getElementById("encrypted_pass").innerHTML = cypher_pass;
	var query_string = "pass=" + cypher_pass;
	query_string += "&tempfile=" + filename;
	query_string += "&user=" + username;
	query_string += "&challenge="+challenge;
	http_request.send(query_string);
    } else {
	alert("error");
    }
}



// Check if username and password are valid and redirect to
// the index page (if valid) or show a error message (otherwise)
function send_login_items(){
	if(http_request.readyState == READY_STATE_COMPLETE) {
		if(http_request.status == 200) {
			var json_response = http_request.responseText;
			// define json_object with ONLY the useful fields
			// none other will get parsed and none will be
			// evaled, just parsed as strings or numbers.
			var json_object = {"valid_user":0};
			// never ever eval anything
			//= eval("("+json_response+")");
			assign_values(json_object, json_response); 
			var valid_user = json_object.valid_user;
			if(valid_user == 1){
				location.href="index.php"
					} else {
				document.getElementById("login_error").style.visibility = "visible";
				document.getElementById("login_error").innerHTML = "<strong>ERROR: </strong>Invalid username or password";
			}
		}
	}
}


function assign_values(spot_object, json_t){
	var i;
	// clumsy but useful for our purposes
	var txt = json_t.replace(/[{}\"]/g,"");
	var assignments = new Array();
	assignments = txt.split(/,/);
	for(i in assignments){
		var var_value_pair = new Array();
		var_value_pair = assignments[i].split(/:/);
		if(spot_object[var_value_pair[0]] != null && var_value_pair[1]){
			spot_object[var_value_pair[0]] = var_value_pair[1];
		}
	}
}
