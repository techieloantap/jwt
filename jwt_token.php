<?php

namespace aw2\jwt;
use \Firebase\JWT\JWT;

\aw2_library::add_service('jwt_token','JWT Library',['namespace'=>__NAMESPACE__]);

\aw2_library::add_service('jwt_token.encode','Encodes the string. Use jwt_token.encode',['namespace'=>__NAMESPACE__]);
function encode($atts,$content=null,$shortcode){
	
	if(\aw2_library::pre_actions('all',$atts,$content,$shortcode)==false)return;
	extract( \aw2_library::shortcode_atts( array(
		'data'=>''
		), $atts) );	
		
		$key=$data['key'];
		$aud = $data['scheme_id'];
	
		//payload
		$payload = array(
			"aud" => $aud,
			"iat" => time(),
			"jti" => "loantap".time()
		);
	
		// create token
		$jwt = JWT::encode($payload, $key);
		return json_encode(array("status"=>"success","message"=>"JWT token generated",'jwt_token'=>$jwt));
}

\aw2_library::add_service('jwt_token','JWT Library',['namespace'=>__NAMESPACE__]);

\aw2_library::add_service('jwt_token.decode','decodes the string. Use jwt_token.decode',['namespace'=>__NAMESPACE__]);
function decode($atts,$content=null,$shortcode){

	if(\aw2_library::pre_actions('all',$atts,$content,$shortcode)==false)return;
	extract( \aw2_library::shortcode_atts( array(
		'data'=>''
		), $atts) );	

	$jwt_token=$data['jwt_token'];
	$key=$data['key'];
	$scheme_id=$data['scheme_id'];
	$decoded = JWT::decode($jwt_token, $key, array('HS256'));
		
	if($decoded->aud!=$data['scheme_id']){
		return json_encode(array("status"=>"error","message"=>"Invalid scheme Id."));
	}
	$mins = (time() - $decoded->iat) / 60;
	
	if($mins > 2){		
		return json_encode(array("status"=>"error","message"=>"Token has been expired."));
	}
		
	return json_encode(array("status"=>"success","message"=>"authentication successful."));

}
