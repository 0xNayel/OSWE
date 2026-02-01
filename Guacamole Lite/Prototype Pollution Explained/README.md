# Prototype Pollution
## Introduction to JavaScript Prototype
In JavaScript, every object is linked to a prototype object, and these prototypes form a chain commonly referred to as the prototype chain. The prototype serves as a template or blueprint for objects. When you create an object using a constructor function or a class, JavaScript automatically sets up a link between the object and its prototype. In the context of our social network example, let's illustrate how prototypes work:
```javascript   
// Prototype for User 
let userPrototype = {
  greet: function() {
    return `Hello, ${this.name}!`;
  }
};

// User Constructor Function
function UserProfilePrototype(name, age, followers, dob) {
  let user = Object.create(userPrototype);
  user.name = name;
  user.age = age;
  user.followers = followers;
  user.dob = dob;
  return user;
}

// Creating an instance
let regularUser = UserProfilePrototype('Ben S', 25, 1000, '1/1/1990');

// Using the prototype method
console.log(regularUser.greet());
```
### Difference between Class and Prototype
**Classes** are like detailed blueprints - they provide a structured, clear way to create objects that all have the same properties and methods. They're predictable and easy to understand since you follow the same template each time.

**Prototypes** are more like starting with a basic model and customizing it directly. Objects are linked through a "prototype chain" to inherit behaviors from other objects. This approach is more flexible and dynamic but can be harder to manage and understand.

Both achieve the same goal of creating objects with shared characteristics, but classes offer structure while prototypes offer flexibility.

### Inheritance
In JavaScript, inheritance allows one object to inherit properties from another, creating a hierarchy of related objects. Continuing with our social network example, let's consider a more specific profile for a content creator. This new object can inherit properties from the general user profile, like `name` and `followers`, and add particular properties, such as `content` and `posts`.
```javascript
let user = {
  name: 'Ben S',
  age: 25,
  followers: 1000,
DoB: '1/1/1990'
};

// Content Creator Profile inheriting from User 
let contentCreatorProfile = Object.create(user);
contentCreatorProfile.content = 'Engaging Content';
contentCreatorProfile.posts = 50;
```
Here, `contentCreatorProfile` inherits properties from the user using `Object.create()`. Now, it has specific properties like `content` and `posts` and inherits `name`, `age`, and `followers` from the general user profile.

This way, inheritance helps create a more specialised object while reusing common properties from a parent object. JavaScript supports both classes and prototype-based inheritance.

- **Prototype-based Inheritance:** In JavaScript, every object has a prototype, and when you create a new object, you can specify its prototype. Objects inherit properties and methods from their prototype. You can use the `Object.create()` method to create a new object with a specified prototype, or you can directly modify the prototype of an existing object using its prototype property.
- **Class-based Inheritance:** JavaScript also supports classes, which provide a more familiar syntax for defining objects and inheritance. Classes in JavaScript are just syntactical sugar over JavaScript's existing prototype-based inheritance. Under the hood, classes still use prototypes.

This represents the prototype-based inheritance in JS:
* A generic `UserProfile` object is defined with shared properties like `email` and `password`.
* A specialized `ContentCreatorProfile` is created using `Object.create(UserProfile)`, setting `UserProfile` as its prototype.
* `ContentCreatorProfile` is given its own property, like `posts`, in addition to inherited ones.
* When accessing a property, JavaScript checks `ContentCreatorProfile` first, then looks up the prototype chain to `UserProfile` if not found.
* This setup allows shared functionality through inheritance while enabling customization for specific profiles.
## Prototype Pollution
Prototype pollution is a vulnerability that arises when an attacker manipulates an object's prototype, impacting all instances of that object. In JavaScript, where prototypes facilitate inheritance, an attacker can exploit this to modify shared properties or inject malicious behaviour across objects.

*Prototype pollution, on its own, might not always present a directly exploitable threat. However, its true potential for harm becomes notably pronounced when it joins with other types of vulnerabilities, such as XSS and CSRF.*
### A Common Example
Let's assume, we have a basic prototype for `Person` with an `introduce` method. The attacker aims to manipulate the behaviour of the `introduce` method across all instances by altering the prototype.
```javascript      
// Base Prototype for Persons
let personPrototype = {
  introduce: function() {
    return `Hi, I'm ${this.name}.`;
  }
};

// Person Constructor Function
function Person(name) {
  let person = Object.create(personPrototype);
  person.name = name;
  return person;
}

// Creating an instance
let ben = Person('Ben');
```
If we copy the above code, paste it into the `console` and hit enter. When we create a new object, `ben`, and call the `introduce` method, it displays `Hi, I'm Ben`

What if an attacker injects malicious content into the introduce method for all instances using the `__proto__` property. In JavaScript, the `__proto__` property is a common way to access the prototype of an object, essentially pointing to the object from which it inherits properties and methods. Let's see, somehow, the attacker executes the following code using any attack vector like XSS, CSRF, etc.
```javascript
// Attacker's Payload
ben.__proto__.introduce=function(){console.log("You've been hacked, I'm Bob");}
console.log(ben.introduce()); 
```
We will discuss in detail what exactly is happening in the background:
- **Prototype Definition:** The `Person` prototype (`personPrototype`) is initially defined with a harmless `introduce` method, introducing the person.
- **Object Instantiation:** An instance of `Person` is created with the name `'Ben' (let ben = Person('Ben');)`.
- **Prototype Pollution Attack:** The attacker injects a malicious payload into the prototype's `introduce` method, changing its behaviour to display a harmful message. We have polluted the `__proto__` property here.
- **Impact on Existing Instances:** As a result, even the existing instance (`ben`) is affected, and calling `ben.introduce()` now outputs the attacker's injected message.

This example shows how an attacker can alter the behaviour of shared methods across objects, potentially causing security risks. Preventing prototype pollution involves carefully validating input data and avoiding directly modifying prototypes with untrusted content.

### Exploitation — XSS
#### **1. Prototype Pollution Basics**

* **JavaScript objects** inherit properties from `Object.prototype`.
* **Critical properties** like `constructor` and `__proto__` can be exploited.
* **Prototype pollution** occurs when user input alters an object’s prototype, affecting all objects that inherit from it.

---

#### **2. The Golden Rule (How Exploitation Works)**

* **Pattern**: `Person[x][y] = val`

  * If `x = "__proto__"`, then `y = property` gets added globally.
* **Advanced**: `Person[x][y][z] = val`

  * If `x = "constructor"`, `y = "prototype"`, `z = newProperty`, you define a new global property.

---

#### **3. Dangerous Functions to Watch**

* **Path-based property setters**, e.g., `_.set(obj, path, value)` from Lodash.

  * If `path` is user-controlled, it can manipulate the object prototype.
* **Example**: `_.set(friend, input.path, input.value)` is risky.

---

#### **4. Real-World Example: Social Media App**

* App allows users to submit reviews:

  ```js
  <form action="/submit-friend-review" method="post">
    <textarea name="reviewContent"></textarea>
  </form>
  ```
* Server code parses the review content:

  ```js
  const input = JSON.parse(reviewContent);
  _.set(friend, input.path, input.value);
  ```

---

#### **5. Attack Payloads**

* **XSS Injection:**

  ```json
  { "path": "reviews[0].content", "value": "<script>alert('Hacked')</script>" }
  ```

  → Stored XSS is triggered when someone visits the profile.

* **Privilege Escalation:**

  ```json
  { "path": "isAdmin", "value": true }
  ```

  → User gains unintended admin privileges.

---

#### **6. Key Takeaways**

* **Prototype pollution** can be combined with **XSS** for greater impact.
* **Unsanitized path inputs** in functions like `_.set()` are major risk points.
* **Always validate** and sanitize user input, especially when modifying object properties.

---
### Exploitation — Property Injection

#### **1. Vulnerable Functions**

##### **Recursive Merge**

* A function like `recursiveMerge(target, source)` merges two objects.
* If `source` contains a `__proto__` key:

  ```json
  { "__proto__": { "newProperty": "value" } }
  ```

  → It pollutes the global prototype. Now all objects inherit `newProperty`.

##### **Object Clone**

* Object cloning (e.g., via `merge()`) can also be exploited.
* Without sanitizing keys like `__proto__` or `constructor`, cloning spreads malicious properties to prototypes.

---

#### **2. Practical Scenario: Cloning Albums**

* In a social app, a user can **clone a friend’s album** by giving it a new name.
* The server:

  * Finds the album.
  * Clones it via object spread `{...album}`.
  * Merges the cloned album with user input (potentially malicious JSON).

##### **Payload Example**

```json
{"__proto__": {"newProperty": "hacked"}}
```

* When merged, this adds `newProperty` to the prototype, not the object itself.

---

#### **3. Effects of the Attack**

* **Shared Across All Objects**: All objects of the same type (e.g., friends) inherit the polluted property.
* **Invisible but Accessible**: `friend.newProperty` works, though it won’t show in `console.log(friend)` unless enumerated.
* **Shows Up in UI**:

  * If the app uses `for...in` (e.g., in EJS templates) to display properties, `newProperty` appears on screen.

---

#### **4. Key Takeaways**

* Recursive merges and deep clones must **filter out dangerous keys** like `__proto__`, `constructor`, and `prototype`.
* **Prototype pollution via merge functions** enables XSS, privilege escalation, and object tampering.
* Always **validate and sanitize** deeply nested user inputs.

---
### Exploitation — Denial of Service

#### **1. Concept Overview**

* **Prototype pollution** lets attackers modify core methods or properties of JavaScript’s global `Object.prototype`.
* If critical methods like `toString()` are overwritten, the **entire application can malfunction or crash**, causing a **Denial of Service**.

---

#### **2. Why `toString()`?**

* `toString()` is **automatically called** in many operations: string interpolation, logging, comparisons, etc.
* If replaced with a non-function value, any code that expects it to behave normally **throws errors or behaves unpredictably**.

---

#### **3. Attack Example**

* In a vulnerable web app with a **clone album** feature:

  * A form accepts a new album name.
  * The backend merges the album with user input using a `merge()` function.

##### **Malicious Payload**

```json
{ "__proto__": { "toString": "Just crash the server" } }
```

* This overrides `Object.prototype.toString`.

#### **Impact**

* The app crashes when it internally or externally calls `toString()` on any object.
* Example error:
  `TypeError: Object.prototype.toString.call is not a function`

---

#### **4. Generalization**

* Other methods like `toJSON`, `valueOf`, and `constructor` can also be targeted.
* But **not all will crash the app**—impact depends on how widely a method is used and whether the code expects it to be a function.

---

### **Key Takeaways**

* **Prototype pollution isn't just about data tampering**—it can break core behavior.
* Overwriting critical methods causes **runtime exceptions** or **infinite loops**, leading to **server crashes** or **resource exhaustion**.
* Always **sanitize input**, especially before merging or cloning user-controlled objects.

---
### Automating the Process

#### **1. Why Automation Is Hard**

* **Prototype pollution is complex and context-dependent**.
* JavaScript's dynamic nature makes it **hard to detect with static patterns**.
* Unlike typical vulnerabilities (e.g., SQLi, XSS), pollution issues often:

  * Involve **deep understanding** of how objects interact.
  * Require **manual code review** to trace property inheritance and manipulation.
* **Security tools help**, but **can't catch everything**—**skilled analysis is essential**.

---

#### **2. Key Tools & Scripts**

| Tool                                                                                                   | Description                                                                                                  |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| 🛡 **[NodeJsScan](https://github.com/ajinabraham/nodejsscan)**                                         | Static code scanner for Node.js apps. Flags known security issues, including prototype pollution.            |
| 🔍 **[Prototype Pollution Scanner (protoscan)](https://github.com/KathanP19/protoscan)**               | Detects patterns in JS codebases vulnerable to pollution. Helps developers audit and secure code.            |
| 💥 **[PPFuzz](https://github.com/dwisiswant0/ppfuzz)**                                                 | Fuzzer that injects various payloads to find pollution bugs in web apps. Effective for black-box testing.    |
| 🌐 **[BlackFan (Client-Side Detection)](https://github.com/BlackFan/client-side-prototype-pollution)** | Focuses on pollution in browser-side JS. Demonstrates XSS and other impacts. Great for client-side research. |

---

#### **3. Pentesting Tips**

* Look for **user input affecting object properties**—especially those used in:

  * `merge()` functions
  * `_.set()` and similar path-based assignments
  * Deep cloning utilities
* Validate and sanitize any input used to define, assign, or clone object properties.
* Focus on:

  * Use of `__proto__`, `constructor`, `prototype`
  * Lack of key filtering in merge/cloning logic

---

### **Takeaway**

* **Automation can aid detection**, but **manual auditing is irreplaceable**.
* Use available tools to narrow down the search, then dive deep with expert analysis to confirm and exploit.

---
### Mitigation Measures

#### For **Pentesters**

Use these tactics to **identify and exploit** prototype pollution:

1. **Input Fuzzing & Manipulation**

   * Test all user inputs, especially those affecting object structures.
   * Use pollution payloads like `{"__proto__": {...}}`.

2. **Context Analysis & Payload Injection**

   * Trace how user inputs affect objects or merge functions.
   * Inject test payloads into those exact contexts.

3. **CSP Bypass Testing**

   * Check for **weak or misconfigured Content Security Policies**.
   * Try injecting scripts even when CSP is enabled.

4. **Dependency Analysis**

   * Identify and exploit **vulnerable third-party libraries**.
   * Prototype pollution bugs often come from outdated packages.

5. **Static Code Analysis**

   * Use tools to find insecure coding patterns in source code (e.g., unsanitized use of `merge`, `set`, or `clone`).

---

#### For **Secure Code Developers**

Focus on **preventing pollution** during development:

1. **Avoid `__proto__`**

   * Never use or trust the `__proto__` property.
   * Use safe alternatives like `Object.getPrototypeOf()`.

2. **Immutable Object Design**

   * Make objects immutable (where possible) to prevent prototype changes.

3. **Encapsulation**

   * Expose only necessary object interfaces.
   * Keep internals and prototype manipulation isolated.

4. **Use Safe Defaults**

   * Initialize objects with secure defaults.
   * Avoid relying on user input for structural object properties.

5. **Input Sanitisation**

   * **Validate and sanitize all user inputs** before using them in merges, assignments, or object creation.

6. **Dependency Management**

   * Regularly **update libraries and frameworks**.
   * Use **well-maintained packages** with active security patches.

7. **Security Headers (e.g., CSP)**

   * Use **Content Security Policy (CSP)** to restrict script sources.
   * Helps prevent exploitation via client-side JS injection.

---

### **Key Takeaway**

> **Prototype pollution is a subtle but powerful attack vector.** Prevention requires a combination of **secure coding practices**, **ongoing testing**, and **vigilance in dependency management**.

---
