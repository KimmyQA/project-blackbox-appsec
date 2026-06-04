# Project BlackBox: Mobile & API Traffic Interception Audit

A hands-on application security (AppSec) portfolio demonstrating HTTPS traffic decryption, API vulnerability analysis, and Man-in-the-Middle (MITM) proxy testing methodologies.

## 📱 Project Core Purpose
This project documents a security analysis of mobile application API communication layers. By routing device telemetry through an intercepting proxy, this audit identifies data leakage, configuration anomalies, and broken authorization states before production deployment.

## 🛠️ Tooling & Architecture
* **Core Interception Tool:** Charles Proxy v4.6
* **Security Framework:** OWASP API Security Top 10
* **Data Log:** `api-audit-log.json` (Structured JSON representation of an identified API vulnerability)

## 🔧 Hands-On Engineering Execution Steps
1. **Network Interception Anchoring:** Configured Charles Proxy as a local listener on port `8888`.
2. **Trust Chain Establishment:** Provisioned a testing endpoint with a local Charles Root Certificate Authority (CA), manually injecting it into the operating system's Trusted Root Certificate Store.
3. **Targeted SSL Proxying:** Isolated traffic capturing to specific application endpoints (`*.mockbank.com`) to filter out noise payloads.
4. **Breakpoint Manipulation:** Implemented dynamic request breakpoints to intercept, analyze, and test API parameters on-the-fly.

## 🚨 Core Security Finding: Broken Object Level Authorization (BOLA)
During traffic analysis of a mock banking module, an IDOR/BOLA flaw was flagged:
* **The Vulnerability:** An authenticated `GET` request to `/v2/accounts/account_id=98711/profile` was intercepted.
* **The Exploit:** Modifying the URL resource query parameter from `98711` to `98712` inside the Charles proxy pane successfully bypassed authorization gates, returning complete profile data of an unauthorized user profile.
* **The Resolution:** Enforced strict server-side relational validation mapping the authenticated caller session directly to requested record ownership entities.
