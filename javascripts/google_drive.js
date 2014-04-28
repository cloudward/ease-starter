var clientId = '1029065291837.apps.googleusercontent.com';
var apiKey = 'AIzaSyAjGB80p-1meHtBWlvjOh1IftM3Gezge3c';
var scopes = 'https://www.googleapis.com/auth/drive';

function handleClientLoad() {
	gapi.client.setApiKey(apiKey);
	window.setTimeout(checkAuth,1);
}

function checkAuth() {
	gapi.auth.authorize({client_id: clientId, scope: scopes, immediate: true},handleAuthResult);
}

function handleAuthResult(authResult) {
	var authorizeButton = document.getElementById('authorizeButton');
    var filePicker = document.getElementById('filePickerLabel');
    filePicker.style.display = 'none';
	if (authResult && !authResult.error) {
		// Access token has been successfully retrieved, requests can be sent to the API.
        filePicker.style.display = 'none';
        filePicker.onchange = uploadFile;
    	authorizeButton.style.visibility = 'hidden';
    	makeApiCall();
	}else{
    	authorizeButton.style.visibility = '';
    	authorizeButton.onclick = handleAuthClick;
	}
}

function handleAuthClick(event) {
	gapi.auth.authorize({client_id: clientId, scope: [scopes], immediate: false}, handleAuthResult);
	return false;
}

function makeApiCall() {  
	gapi.client.load('drive', 'v2', makeRequest);   
}

function makeRequest()
{
	var request = gapi.client.request({
	        'path': '/drive/v2/files',
	        'method': 'GET',
	        'params': {'maxResults': '50'}
		});

	request.execute(function(resp) { 
		/** append to table here **/
		var oTable = jQuery('#mediaTable').dataTable({
			"bRetrieve": true,
			"bJQueryUI": true,
			"sPaginationType": "full_numbers"
		});
		//oTable.fnClearTable();
    	if(resp.items.length > 0){
			for(i=0; i<resp.items.length; i++) {
        		var tnail = resp.items[i].thumbnailLink;
        		var title = resp.items[i].title;
        		var lmodu = resp.items[i].lastModifyingUserName;
        		var lmoddate = resp.items[i].modifiedDate;

				oTable.fnAddData(["<img src='"+tnail+"'/>", title, lmodu, lmoddate]);
    		}
		}
			
	});    
}

/**
	* Start the file upload.
	*
	* @param {Object} evt Arguments from the file selector.
*/
function uploadFile(evt) {
	alert('here');
	gapi.client.load('drive', 'v2', function() {
		var file = evt.target.files[0];
		insertFile(file);
	});
}

/**
	* Insert new file.
	*
	* @param {File} fileData File object to read data from.
	* @param {Function} callback Function to call when the request is complete.
*/
function insertFile(fileData, callback) {
	const boundary = '-------314159265358979323846';
    const delimiter = "\r\n--" + boundary + "\r\n";
    const close_delim = "\r\n--" + boundary + "--";

    var reader = new FileReader();
    reader.readAsBinaryString(fileData);
    reader.onload = function(e){
    	var contentType = fileData.type || 'application/octet-stream';
      	var metadata = {
        	'title': fileData.name,
        	'mimeType': contentType
      	};

      	var base64Data = btoa(reader.result);
      	var multipartRequestBody = delimiter + 'Content-Type: application/json\r\n\r\n' + JSON.stringify(metadata) + delimiter + 'Content-Type: ' + contentType + '\r\n' + 'Content-Transfer-Encoding: base64\r\n' + '\r\n' + base64Data + close_delim;
      	var request = gapi.client.request({
          	'path': '/upload/drive/v2/files',
          	'method': 'POST',
          	'params': {
				'uploadType': 'multipart'
			},
          	'headers': {
            	'Content-Type': 'multipart/mixed; boundary="' + boundary + '"'
          	},
          	'body': multipartRequestBody
		});
		
      	if (!callback){
        	callback = function(file) {
          		//console.log(file)
        	};
      	}

      request.execute(callback);
	}
}

/**
	* Retrieve a list of File resources.
	*
	* @param {Function} callback Function to call when the request is complete.
*/
function retrieveAllFiles(callback){
	var retrievePageOfFiles = function(request, result){
		request.execute(function(resp){
	    	result = result.concat(resp.items);
	      	var nextPageToken = resp.nextPageToken;
	      	if (nextPageToken){
	        	request = gapi.client.drive.files.list({
	          		'pageToken': nextPageToken
	        	});
	        	retrievePageOfFiles(request, result);
	      	}else{
	        	callback(result);
				var containerHeight = jQuery("body").height();
				containerHeight = containerHeight + 40;
				jQuery("#footerBar").css("top", containerHeight);
	      	}
	    });
	}
	var initialRequest = gapi.client.drive.files.list();
	retrievePageOfFiles(initialRequest, []);
}