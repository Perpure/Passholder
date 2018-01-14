/*
Copyright (C) 2017-2018 Pavel Dyachek GPL 3.0+

This file is part of PassHolder.

    PassHolder is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    PassHolder is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with PassHolder.  If not, see <http://www.gnu.org/licenses/>.
*/
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
