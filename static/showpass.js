function req_ajax_json(id){
    var req = $.ajax({
        url: "/ajax/json/?id="+id,
        dataType: "json"
    });
    req.done(function(json_data){
        // TODO: обработка защиты от неправильного айдишника
        $("#"+json_data.id).text("")
        $("#"+json_data.id).append(json_data.password)
    });
};
