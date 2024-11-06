/*
 * JavaScript for the general website
 */
$( document ).ready(function() {
    $( ".loading_bar" ).fadeOut();
    prettyPrint();
});

function hide_loading_bar() {
    $( ".loading_bar" ).fadeOut();
}

function show_loading_bar() {
    $( ".loading_bar" ).fadeIn();
}

function set_loading_bar() {

}

/*
 * Main GoHunt JavaScript
 * ( for the actual app )
 */
USER = {};

function getCSRFToken() {
   let potential_token = $("#csrf_token").val() 
   if(potential_token === null) {
    return null
   }

   return potential_token
}

function api_request( method, path, data, callback ) {
    show_loading_bar();
    header_data = {};

    let CSRF_TOKEN = getCSRFToken()
    if( CSRF_TOKEN != "" ) {
        header_data["X-CSRF-Token"] = CSRF_TOKEN;
    }

    if( method == "GET" ) {
        content_type = "application/x-www-form-urlencoded"
        send_data = $.param( data );
    } else {
        content_type = "application/json; charset=utf-8"
        send_data = JSON.stringify( data );
    }

    $.ajax({
        url: path,
        type: method,
        headers: header_data,
        data: send_data,
        timeout: 500,
        cache: false,
        xhrFields: {
            withCredentials: true
        },
        contentType: content_type,
        dataType: "json",
        success: function (data) {
            hide_loading_bar();
            callback( data );
        },
        error: function (XMLHttpRequest) {
            hide_loading_bar();

            let errorText = "An unknown error occured"
            if (XMLHttpRequest.readyState == 4 || XMLHttpRequest.readyState == 0) {
                // HTTP error (can be checked by XMLHttpRequest.status and XMLHttpRequest.statusText)
                errorText = XMLHttpRequest.statusText
            }

            callback({"error":errorText});
        }
    });
}
