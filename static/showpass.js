function req_ajax_json(){
    var req = $.ajax({
        url: "/ajax/json",
        dataType: "json"
    });
    req.done(function(json_data){
        $("#ajax_content").text("")
        $("#ajax_content").append("test: "+json_data.password)
    });
};
