<?php

/** merchant management application processor **/
class mmsApplicationProcessor{
	
	/** class varialbes **/
	public $parser;
	public $responseObj;
	public $endPoint;
	public $mmsId;
	public $action;
	
	public function __construct(&$parser, $params){
		
		/** init class variables **/
		$this->parser = $parser;
		$this->responseObj = array();
		$this->endPoint = 'https://secure.cloudward.com/billing/webservices/registration/';
		$this->action = $params['action'];
		$this->request = $params['request'];
		$this->postData = $params;
		
	}
	
	public function processApplication(){
		switch($this->request){
			case "createApplication":
				$this->postData['request'] = 'createMmsAccount';
				break;
			case "updateApplication":
				$this->postData['request'] = 'updateMmsAccount';
				break;
			case "getApplication":
				$this->postData['request'] = 'getMmsAccount';
				break;
		}
		$apiResponse = self::apiCaller();
		return $apiResponse;
	}
	
	
	public function apiCaller(){
		//request data
		$data = $this->responseObj;

		//build query for request data
		$data = http_build_query($this->postData);

		//build context for stream
		$context = [
		  'http' => [
		    'method' => 'POST',
		    'header' => "Content-type: application/x-www-form-urlencoded",
		    'content' => $data
		  ]
		];

		//create stream context
		$context = stream_context_create($context);

		//execute call to installer
		$result = file_get_contents($this->endPoint, false, $context);

		return $result;
	}
	
}

