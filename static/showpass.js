function req_ajax_json(){
    var req = $.ajax({
        url: "/ajax/json",
        dataType: "json"
    });
    req.done(function(json_data){
        $(json_data.id).text("")
        $(json_data.id).append(json_data.password)
    });
};
