# =========================================================================
# File: local.rules
# Application: ShopSecure Next.js Web Application
# Author: SecOps Team
# Description: Custom NIDS signatures for OWASP Top 10 Web Vulnerabilities
# Last Updated: 2026-09-30
# =========================================================================

# --- [ Reconnaissance & Probing ] ---
alert icmp any any -> any any (msg:"[ShopSecure SOC] ICMP Echo Request (Ping) - Possible Host Recon"; itype:8; classtype:attempted-recon; sid:1000010; rev:2;)

# --- [ OWASP A01: Broken Access Control ] ---
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A01 - Directory Traversal Attempt (/etc/passwd)"; flow:established,to_server; http.uri; content:"../"; content:"/etc/passwd"; classtype:attempted-recon; metadata:severity high; sid:1000011; rev:1;)
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A01 - Admin Panel Forceful Browsing"; flow:established,to_server; http.uri; content:"/admin"; nocase; http.method; content:"GET"; classtype:web-application-activity; metadata:severity medium; sid:1000012; rev:1;)

# --- [ OWASP A03: Injection (SQLi, XSS, OS Command) ] ---
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A03 - SQL Injection (UNION SELECT)"; flow:established,to_server; http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; metadata:severity critical; sid:1000013; rev:1;)
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A03 - SQL Injection (Always True Tautology)"; flow:established,to_server; http.uri; content:"OR"; nocase; content:"1=1"; nocase; distance:0; classtype:web-application-attack; metadata:severity critical; sid:1000014; rev:1;)
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A03 - Cross-Site Scripting (XSS) Payload"; flow:established,to_server; http.uri; content:"<script>"; nocase; classtype:web-application-attack; metadata:severity high; sid:1000015; rev:1;)
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A03 - OS Command Injection (/bin/sh)"; flow:established,to_server; http.uri; content:"/bin/sh"; classtype:web-application-attack; metadata:severity critical; sid:1000016; rev:1;)

# --- [ OWASP A05: Security Misconfiguration ] ---
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A05 - Exposed Environment File (.env) Access Attempt"; flow:established,to_server; http.uri; content:".env"; classtype:web-application-activity; metadata:severity high; sid:1000017; rev:1;)

# --- [ OWASP A07: Identification and Authentication Failures ] ---
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A07 - Credential Stuffing / Default Admin Login Attempt"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/api/auth/login"; http.request_body; content:"admin"; nocase; classtype:suspicious-login; metadata:severity high; sid:1000018; rev:1;)

# --- [ OWASP A10: Server-Side Request Forgery (SSRF) ] ---
alert http any any -> any any (msg:"[ShopSecure SOC] OWASP A10 - SSRF Attempt (AWS Cloud Metadata Query)"; flow:established,to_server; http.uri; content:"169.254.169.254"; classtype:web-application-attack; metadata:severity critical; sid:1000019; rev:1;)

# =========================================================================
# EOF
# =========================================================================
