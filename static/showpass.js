function req_ajax_json(id){
    var req = $.ajax({
        url: "/ajax/json/?id="+id+"&cont="+document.getElementById("showid"+id).innerHTML,
        dataType: "json"
    });
    req.done(function(json_data){
        $("#"+json_data.id).text(json_data.password)
        $("#showid"+json_data.id).text(json_data.show)
    });
};
