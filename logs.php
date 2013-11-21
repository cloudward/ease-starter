<?php

require_once 'google/appengine/api/log/LogService.php';
require_once 'google/appengine/util/string_util.php';

use google\appengine\api\log\LogService;
use google\appengine\util as util;

require_once('ease/core.class.php');
$ease_core = new ease_core();

$notification_email = trim($ease_core->process_ease('<# apply webstyle.fb7fbd7a3bed0f0c9cf0180d26a6d9c1 as "webstyle" .#><#[webstyle.notification_site_email]#>',true));

date_default_timezone_set('Australia/Sydney');
session_start();
$notification_email = "";
if($_SESSION['keypassn'] != "554bd8fc3801fd2e560154e42a32670ab554bd8fc3801fd2e560154e42a32670ab" && $notification_email){
  echo "You need to login before you can access this page";
  exit;
}else{
  $notification_email = trim($ease_core->process_ease('<#[cookie.email]#>',true));
  
  if(!$notification_email){
    $notification_email = $_POST['support_contact_email'];
  }
  
  $has_style = false;
}

if(!$notification_email){
  echo "No email address found";
  exit;
}
$application_id = str_replace("~s","",$_SERVER['APPLICATION_ID']);

// Get time range from querystrings
$start = (float) $_GET["start"];
$end = (float) $_GET["end"];

// Each level corresponds to the message with the same index.
$levels = explode(' ', $_GET['levels']);
$messages = "0 1";
$messages = explode(' ', $messages);


// Both 'messages' and 'levels' must have the same number of elements.
if (count($messages) !== count($levels)) {
 // echo 'Got ' . count($messages) . 'messages ' . count($levels) . ' levels.';
  //return;
}

// An empty string explodes to a single empty element.
if (empty($messages[0])) {
  $messages = [];
  $levels = [];
}


if (isset($_GET['min'])) {
  $options['minimum_log_level'] = (int) $_GET['min'];
}

$options = [
  'include_app_logs' => true
];
$logs = LogService::fetch($options);

// The fetched messages that match each expected message in $messages.
$matches = [];

$message = array();

$message[$application_id] = array();
$full_message_text = "";
foreach ($logs as $log) {
    
    $app_logs = $log->getAppLogs();
    $start_date_time = $log->getStartDateTime();
    $end_date_time = $log->getEndDateTime();
//var_dump($end_date_time->format('c'));
    if ($start_date_time->getTimestamp() > $end_date_time->getTimestamp()) {
      echo 'Start date ' . $start_date_time->format('c') .
          ' after end date ' . $end_date_time->format('c');
      return;
    }

    if (!$log->getIp()) {
      echo "No ip";
      return;
    }

    if (!$log->getOffset()) {
      die("No offset");
    }

    if ($log->getLatencyUsec() <= 0) {
      die("No latency");
    }

    $message_text = "Start Time: " . $start_date_time->format('c')  . "/End time: " . $end_date_time->format('c'). " ";
    //var_dump($app_logs[0]->getMessage());
    foreach ($app_logs as $app_log) {
      $num_matches = count($matches);
      //if ($num_matches >= count($messages)) {
      //  die('Too many app logs. Expected: ' . print_r($messages, true) .
      //      ' Found: ' . print_r($app_logs, true));
      //}

      //if ($app_log->getMessage() !== $messages[$num_matches]) {
      //  die('Message mismatch. Expected: ' . $messages[$num_matches] .
      //      ' Got: ' . $app_log->getMessage());
      //}

      // Translate syslog to GAE log level.
      //$gaeLevel = LogService::getAppEngineLogLevel((int) $levels[$num_matches]);
      //if ($app_log->getLevel() !== $gaeLevel) {
      //  die('Level mismatch. Expected: ' . $gaeLevel .
      //      ' Got: ' . $app_log->getLevel());
      //}
      $message_text .= $app_log->getMessage() . "";
      $matches[] = $app_log->getMessage();
      
    }
    
    $message[$application_id][] = $message_text;
    $full_message_text .= htmlspecialchars($message_text) . "<BR><BR>";
  }
  
  
  //var_dump(json_encode($message));

  $full_message_text = "Application ID: " . $application_id . "<BR>Submitted by: " . htmlspecialchars($_POST['support_contact_email']) . "<BR>Problem: " . htmlspecialchars($_POST['support_desc']) . "<BR><BR>" . $full_message_text;
  $ease_code = '<#

		send email;
			from_name = "' . $notification_email . '";
			to = "support@cloudward.com";
			subject = "Starter App Support Email";
			type = "html"; // text or html
			body = "' . str_replace('"','\'',$full_message_text) . '";
		
	#>';
  $ease_core->process_ease($ease_code,true);

if(!$has_style){
header("Location: /?page=___deleteaftersetup_support_received");
}else{
header("Location: /?page=admin_support_received");
}
exit;
//// Finish if we have read all expected messages.
//if ($matches === $messages) {
//  echo 'PASS';
//} else {
//  die('Expected messages:' . print_r($messages, true) . "\n" .
//      'Found:' . print_r($matches, true));
//}
?>