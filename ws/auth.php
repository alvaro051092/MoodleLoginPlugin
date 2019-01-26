<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authentication Plugin: External Webservice Authentication
 *
 * Checks against an external webservice.
 *
 * @package    auth_ws
 * @author     Daniel Neis Araujo
 * @license    http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');


/**
 * External webservice authentication plugin.
 */
class auth_plugin_ws extends auth_plugin_base {

	

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'ws';
        $this->config = get_config('auth/ws');

        if (isset($this->config->default_params) && !empty($this->config->default_params)) {
            $params = explode(',', $this->config->default_params);
            $defaultparams = array();
            foreach ($params as $p) {
                list($paramname, $value) = explode(':', $p);
                $defaultparams[$paramname] = $value;
            }
            $this->config->ws_default_params = $defaultparams;
        } else {
            $this->config->ws_default_params = array();
        }
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password) {
		
		//VALIDO LA URL
		$error = false;
		
		if( empty( $this->config->auth_serverurl ) ){
			$error = true;
		}

		$ch = curl_init( $this->config->auth_serverurl . "login" );
	 
		//Establecer un tiempo de espera
		curl_setopt( $ch, CURLOPT_TIMEOUT, 5 );
		curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 5 );

		//establecer NOBODY en true para hacer una solicitud tipo HEAD
		curl_setopt( $ch, CURLOPT_NOBODY, true );
		//Permitir seguir redireccionamientos
		curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
		//recibir la respuesta como string, no output
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );

		$data = curl_exec( $ch );

		//Obtener el código de respuesta
		$httpcode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		//cerrar conexión
		curl_close( $ch );

		//Aceptar solo respuesta 200 (Ok), 301 (redirección permanente) o 302 (redirección temporal)
		$accepted_response = array( 200, 301, 302 );
		if( in_array( $httpcode, $accepted_response ) ) {
			$error = false;
		} else {
			$error = true;
		}
		
		
		
		
		if($error)
		 {	
			throw new Exception("URL no accesible: " . $this->config->auth_serverurl . "login");
		}
		else
		{
			$initialVector 	= "a#!?d./*@@^^''_a";
			$salt 			= "-KeY!!AD#AM!!KeY";
			$separador		= "#||#";
			
			$tknUsr 	= $this->config->username;//$tknUsr 	= "ws_mdl";
			$tknPsw	 	= $this->config->password;//$tknPsw	 	= "$.WSusMdl%";
			
			$pUsuario = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$username,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);

			$pPassword = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$password,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);
									
			$tknUsr = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$tknUsr,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);
									
			$tknPsw = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$tknPsw,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);

			
			$token = $tknUsr . $separador . $tknPsw;
			
			$token = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$token,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);


			//PARAMETROS
			$tkn = $token;
			$usr = $pUsuario;
			$psw = $pPassword;
			
			$paramsEncode = "?tkn=" . urlencode($tkn) . "&usr=" . urlencode($usr) . "&psw=" . urlencode($psw);
			
			//URL
			//$service_url = 'http://192.168.0.100:8084/GestionAcademica/rest/persona/login';
			$service_url = $this->config->auth_serverurl . "login";
			
			
			$result = $this->call_ws($service_url,  $paramsEncode);
			
			if($result == null) return false;
			
			
			return ($result->mensaje->tipoMensaje == "MENSAJE");
			
		}
		
		return false;
			
		
    }

    /**
     * This plugin is intended only to authenticate users.
     * User synchronization must be done by external service,
     * using Moodle's webservices.
     *
     * @param progress_trace $trace
     * @param bool $do_updates  Optional: set to true to force an update of existing accounts
     * @return int 0 means success, 1 means failure
     */
    public function sync_users(progress_trace $trace, $do_updates=false) {
        return true;
    }

    public function get_userinfo($username) {
        return array();
    }

    private function call_ws($service_url, $params) {

        try {
			$service_url = $service_url . $params;	
			error_log("Url a consumir: " . $service_url, 0);


			$curl = curl_init($service_url);
			
			
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
			
			
			$curl_response = curl_exec($curl);
			
			error_log("Dato: " . $curl_response, 0);
			
			if ($curl_response === false) {
				$info = curl_getinfo($curl);
				curl_close($curl);
				die('error occured during curl exec. Additioanl info: ' . var_export($info));
			}
			
			curl_close($curl);
			
			$decoded = new SimpleXMLElement($curl_response);
			
			return $decoded;
			
		} catch (Exception $e) {
			echo $e->getMessage();
			error_log("Error: " . $e->getMessage(), 0);
        }
		
		return null;
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     *
     * @param stfdClass $form
     * @param array $err errors
     * @return void
     */
    public function validate_form($form, &$err) {
    }

    public function prevent_local_passwords() {
        return true;
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    public function is_internal() {
        return false;
    }

    /**
     * Indicates if moodle should automatically update internal user
     * records with data from external sources using the information
     * from auth_plugin_base::get_userinfo().
     * The external service is responsible to update user records.
     *
     * @return bool true means automatically copy data from ext to user table
     */
    public function is_synchronised_with_external() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    public function can_change_password() {
        return ($this->config->canchangepassword == 'SI');
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    public function change_password_url() {
		global $USER, $separador;
        if (isset($this->config->changepasswordurl) && isset($USER->username) && !empty($this->config->changepasswordurl)) {
            
			$initialVector 	= "a#!?d./*@@^^''_a";
			$salt 			= "-KeY!!AD#AM!!KeY";
			$separador		= "#||#";
		
			error_log('Cambiando contraseña -> ' . $separador, 0);
			error_log('Al usuario ' . $USER->username, 0);
			
			
			$tknUsr 	= $this->config->username;//$tknUsr 	= "ws_mdl";
			$tknPsw	 	= $this->config->password;//$tknPsw	 	= "$.WSusMdl%";
			
			

			$pUsuario = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$USER->username,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);
									
			$tknUsr = base64_encode(
									mcrypt_encrypt( 
										MCRYPT_RIJNDAEL_128,
										$salt,
										$tknUsr,  
										MCRYPT_MODE_CFB,
										$initialVector
									)
								);
								
			$tknPsw = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$tknPsw,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);

			
			$token = $tknUsr . $separador . $tknPsw;
			
			$token = base64_encode(
										mcrypt_encrypt( 
											MCRYPT_RIJNDAEL_128,
											$salt,
											$token,  
											MCRYPT_MODE_CFB,
											$initialVector
										)
									);
			
			
			$paramsEncode = "?tkn=" . urlencode($token) . "&usr=" . urlencode($pUsuario);
			
			$service_url = $this->config->auth_serverurl . "token";			
			
			$result = $this->call_ws($service_url,  $paramsEncode);
			
			if($result == null) return null;
		
		
			if($result->mensaje->tipoMensaje == "ERROR")
			{
				error_log("Error: " . $result->mensaje->mensaje, 0);
				return null;
			}
			else{
				
				$paramsEncode = "?tkn=" . urlencode($result->objeto) . "&usr=" . urlencode($pUsuario);
				
				$url_psw = $this->config->changepasswordurl . $paramsEncode;
			
				return new moodle_url($url_psw);
			}
			
			
        } else {
            return null;
        }
    }
	
	
	
	

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    public function can_reset_password() {
        return false;
    }
	
	
	
	
	
	

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param stdClass $config
     * @param array $err errors
     * @param array $user_fields
     * @return void
     */
    public function config_form($config, $err, $user_fields) {
        include 'config.html';
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param srdClass $config
     * @return bool always true or exception
     */
    public function process_config($config) {
        if (!isset($config->auth_serverurl)) {
            $config->auth_serverurl = '';
        }
        if (!isset($config->username)) {
            $config->username = '';
        }
        if (!isset($config->password)) {
            $config->password = '';
        }
       if (!isset($config->changepasswordurl)) {
            $config->changepasswordurl = '';
        }
		if (!isset($config->canchangepassword)) {
            $config->canchangepassword = '';
        }

        set_config('auth_serverurl',        $config->auth_serverurl,    'auth/ws');
        set_config('username', 				$config->username, 			'auth/ws');
        set_config('password', 				$config->password, 			'auth/ws');
        set_config('changepasswordurl',     $config->changepasswordurl, 'auth/ws');
		set_config('canchangepassword',     $config->canchangepassword, 'auth/ws');

        return true;
    }
}
