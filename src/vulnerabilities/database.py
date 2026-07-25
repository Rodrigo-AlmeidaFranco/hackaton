"""
Vulnerability knowledge base: maps architecture component types to
STRIDE threats, CVE patterns, and specific countermeasures.
"""

from typing import Dict, List


# STRIDE categories
STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

# Each entry: list of threat dicts per component
# Fields: stride_category, threat_name, description, severity, countermeasures, cwe_ids
COMPONENT_THREATS: Dict[str, List[dict]] = {
    "user": [
        {
            "stride_category": "S",
            "threat_name": "Identity Spoofing / Credential Theft",
            "description": "An attacker impersonates a legitimate user by stealing or guessing credentials (phishing, brute-force, credential stuffing).",
            "severity": "High",
            "countermeasures": [
                "Enforce Multi-Factor Authentication (MFA)",
                "Implement account lockout after N failed attempts",
                "Use password hashing with bcrypt/argon2",
                "Educate users about phishing attacks",
                "Monitor and alert on suspicious login patterns",
            ],
            "cwe_ids": ["CWE-287", "CWE-521"],
        },
        {
            "stride_category": "R",
            "threat_name": "Repudiation of User Actions",
            "description": "User denies having performed an action (transaction, data deletion) with no audit trail to prove otherwise.",
            "severity": "Medium",
            "countermeasures": [
                "Implement tamper-proof audit logging for all user actions",
                "Use digital signatures for critical operations",
                "Store logs in an immutable, separate storage",
                "Issue receipts/acknowledgments for important transactions",
            ],
            "cwe_ids": ["CWE-778"],
        },
        {
            "stride_category": "E",
            "threat_name": "Privilege Escalation via Session Hijacking",
            "description": "Attacker steals a valid session token (XSS, MITM) and gains elevated access.",
            "severity": "High",
            "countermeasures": [
                "Set HttpOnly and Secure flags on session cookies",
                "Use SameSite=Strict cookie attribute",
                "Implement short session timeouts with refresh tokens",
                "Regenerate session ID after privilege level changes",
                "Use HTTPS everywhere (HSTS)",
            ],
            "cwe_ids": ["CWE-384", "CWE-613"],
        },
    ],

    "web_server": [
        {
            "stride_category": "T",
            "threat_name": "Code / Command Injection",
            "description": "Attacker injects malicious code (SQL, OS commands, template expressions) through unvalidated inputs processed by the application.",
            "severity": "Critical",
            "countermeasures": [
                "Use parameterized queries / prepared statements",
                "Validate and sanitize all user inputs",
                "Apply input allow-listing, not deny-listing",
                "Run application with least-privilege OS user",
                "Use a WAF to detect and block injection patterns",
                "Enable Content Security Policy (CSP) headers",
            ],
            "cwe_ids": ["CWE-89", "CWE-78", "CWE-94"],
        },
        {
            "stride_category": "I",
            "threat_name": "Sensitive Data Exposure via Error Messages",
            "description": "Verbose error messages, stack traces, or debug endpoints reveal internal architecture, file paths, or credentials.",
            "severity": "Medium",
            "countermeasures": [
                "Disable debug mode in production",
                "Return generic error messages to clients",
                "Log details server-side only with proper access controls",
                "Remove/secure development endpoints (Swagger, actuator, etc.)",
                "Scan for exposed secrets with tools like truffleHog",
            ],
            "cwe_ids": ["CWE-209", "CWE-532"],
        },
        {
            "stride_category": "D",
            "threat_name": "Denial of Service (DoS/DDoS)",
            "description": "Attackers overwhelm the server with requests, or exploit resource-intensive operations to exhaust CPU, memory, or connections.",
            "severity": "High",
            "countermeasures": [
                "Implement rate limiting and request throttling",
                "Use a CDN with DDoS protection (AWS Shield, Cloudflare)",
                "Configure connection timeouts and max request sizes",
                "Scale horizontally with auto-scaling groups",
                "Implement CAPTCHA for sensitive endpoints",
            ],
            "cwe_ids": ["CWE-400", "CWE-770"],
        },
        {
            "stride_category": "E",
            "threat_name": "Remote Code Execution via Dependency Vulnerabilities",
            "description": "Outdated libraries or frameworks with known CVEs allow attackers to execute arbitrary code on the server.",
            "severity": "Critical",
            "countermeasures": [
                "Maintain an updated Software Bill of Materials (SBOM)",
                "Automate dependency scanning (Dependabot, Snyk, OWASP DC)",
                "Apply security patches promptly",
                "Use minimal base images for containers",
                "Enable runtime security monitoring (Falco, etc.)",
            ],
            "cwe_ids": ["CWE-1104", "CWE-502"],
        },
    ],

    "database": [
        {
            "stride_category": "T",
            "threat_name": "SQL Injection / NoSQL Injection",
            "description": "Malicious queries manipulate, delete, or exfiltrate data by injecting commands through unvalidated application inputs.",
            "severity": "Critical",
            "countermeasures": [
                "Use ORM with parameterized queries exclusively",
                "Principle of least privilege: DB user has only required permissions",
                "Deploy a database firewall / proxy",
                "Regular penetration testing and DAST scans",
                "Enable query auditing and anomaly detection",
            ],
            "cwe_ids": ["CWE-89", "CWE-943"],
        },
        {
            "stride_category": "I",
            "threat_name": "Unauthorized Data Access / Data Breach",
            "description": "Sensitive data is accessed by unauthorized users due to missing access controls, unencrypted storage, or backup exposure.",
            "severity": "Critical",
            "countermeasures": [
                "Encrypt data at rest (AES-256) and in transit (TLS 1.3)",
                "Implement row-level and column-level security",
                "Use database secrets management (AWS Secrets Manager, Vault)",
                "Disable public network access to the database",
                "Mask sensitive data in non-production environments",
            ],
            "cwe_ids": ["CWE-312", "CWE-359"],
        },
        {
            "stride_category": "D",
            "threat_name": "Database DoS via Resource Exhaustion",
            "description": "Expensive or unbounded queries exhaust database resources, causing service unavailability.",
            "severity": "High",
            "countermeasures": [
                "Set query timeouts and row limits",
                "Implement connection pooling",
                "Monitor slow queries and set alerts",
                "Use read replicas for read-heavy workloads",
                "Deploy a caching layer to reduce DB load",
            ],
            "cwe_ids": ["CWE-400"],
        },
    ],

    "api_gateway": [
        {
            "stride_category": "S",
            "threat_name": "API Key / Token Forgery",
            "description": "Attacker uses stolen, forged, or leaked API keys/JWT tokens to authenticate as a legitimate service or user.",
            "severity": "High",
            "countermeasures": [
                "Rotate API keys regularly and on suspected compromise",
                "Use short-lived JWT tokens with proper signature validation",
                "Implement OAuth 2.0 with scopes",
                "Store API keys in secrets management systems, never in code",
                "Detect and alert on unusual API usage patterns",
            ],
            "cwe_ids": ["CWE-345", "CWE-347"],
        },
        {
            "stride_category": "T",
            "threat_name": "Request Tampering / Parameter Pollution",
            "description": "Attacker modifies API request parameters (HTTP parameter pollution, mass assignment) to bypass business logic.",
            "severity": "High",
            "countermeasures": [
                "Validate and whitelist all input parameters at the gateway",
                "Implement strict input schema validation (OpenAPI/JSON Schema)",
                "Avoid mass assignment patterns in backend services",
                "Sign requests with HMAC for integrity verification",
            ],
            "cwe_ids": ["CWE-235", "CWE-915"],
        },
        {
            "stride_category": "D",
            "threat_name": "API Abuse / Rate Limit Bypass",
            "description": "Attacker bypasses rate limits to abuse APIs for scraping, brute-force, or resource exhaustion.",
            "severity": "Medium",
            "countermeasures": [
                "Enforce per-client rate limits at the gateway level",
                "Implement adaptive rate limiting based on behavior",
                "Use IP reputation lists and geo-blocking where appropriate",
                "Apply quotas per API key/subscription plan",
            ],
            "cwe_ids": ["CWE-770"],
        },
        {
            "stride_category": "I",
            "threat_name": "API Documentation / Schema Exposure",
            "description": "Publicly accessible Swagger/OpenAPI docs expose endpoint structure, auth mechanisms, and data models.",
            "severity": "Low",
            "countermeasures": [
                "Restrict API documentation to authenticated users",
                "Remove sensitive examples from API docs",
                "Disable auto-generated docs in production if not needed",
            ],
            "cwe_ids": ["CWE-200"],
        },
    ],

    "load_balancer": [
        {
            "stride_category": "S",
            "threat_name": "SSL Stripping / TLS Downgrade",
            "description": "Attacker in a MITM position forces the connection to downgrade from HTTPS to HTTP, exposing traffic.",
            "severity": "High",
            "countermeasures": [
                "Enforce HTTPS-only with HSTS headers (includeSubDomains, preload)",
                "Configure minimum TLS 1.2, prefer TLS 1.3",
                "Disable weak cipher suites at the load balancer",
                "Use certificate pinning for mobile clients",
            ],
            "cwe_ids": ["CWE-326", "CWE-295"],
        },
        {
            "stride_category": "D",
            "threat_name": "SYN Flood / Connection Exhaustion",
            "description": "Attacker sends massive TCP SYN packets, exhausting the load balancer's connection table.",
            "severity": "High",
            "countermeasures": [
                "Enable SYN cookies on the load balancer",
                "Deploy upstream DDoS scrubbing (AWS Shield Advanced, Cloudflare)",
                "Set aggressive connection timeouts",
                "Use Anycast routing for traffic distribution",
            ],
            "cwe_ids": ["CWE-400"],
        },
        {
            "stride_category": "I",
            "threat_name": "Sensitive Header / Log Leakage",
            "description": "Load balancer access logs contain sensitive headers (Authorization, cookies) stored in plain text.",
            "severity": "Medium",
            "countermeasures": [
                "Mask sensitive headers in access logs",
                "Restrict access to load balancer logs",
                "Forward only necessary headers to backend services",
                "Strip internal headers from external requests",
            ],
            "cwe_ids": ["CWE-532"],
        },
    ],

    "cache": [
        {
            "stride_category": "I",
            "threat_name": "Cache Poisoning / Sensitive Data in Cache",
            "description": "Attacker injects malicious content into the cache or accesses cached sensitive data belonging to other users.",
            "severity": "High",
            "countermeasures": [
                "Never cache responses containing user-specific sensitive data",
                "Validate cache keys to prevent poisoning",
                "Set appropriate Cache-Control headers (no-store for sensitive data)",
                "Encrypt data stored in the cache",
                "Isolate cache instances per tenant in multi-tenant systems",
            ],
            "cwe_ids": ["CWE-524", "CWE-441"],
        },
        {
            "stride_category": "T",
            "threat_name": "Cache Injection / Key Collision",
            "description": "Attacker manipulates cache keys to serve tampered responses to legitimate users.",
            "severity": "Medium",
            "countermeasures": [
                "Sanitize all inputs used in cache key construction",
                "Use namespaced cache keys",
                "Implement cache TTLs appropriate to data sensitivity",
            ],
            "cwe_ids": ["CWE-345"],
        },
        {
            "stride_category": "D",
            "threat_name": "Cache Stampede / Thundering Herd",
            "description": "Simultaneous cache misses cause all requests to hit the backend simultaneously, causing overload.",
            "severity": "Medium",
            "countermeasures": [
                "Implement cache locking (mutex) for popular keys",
                "Use probabilistic early expiration",
                "Warm up cache before deploying new versions",
                "Set jittered TTLs to prevent synchronized expiration",
            ],
            "cwe_ids": ["CWE-400"],
        },
    ],

    "firewall": [
        {
            "stride_category": "T",
            "threat_name": "Firewall Rule Bypass via Tunneling",
            "description": "Attacker encapsulates malicious traffic inside allowed protocols (DNS, HTTP, ICMP) to bypass firewall rules.",
            "severity": "High",
            "countermeasures": [
                "Implement deep packet inspection (DPI)",
                "Monitor DNS traffic for data exfiltration patterns",
                "Use an application-layer firewall (WAF) in addition to network firewall",
                "Restrict outbound traffic to known destinations",
                "Monitor and alert on unusual protocol usage",
            ],
            "cwe_ids": ["CWE-693"],
        },
        {
            "stride_category": "E",
            "threat_name": "Firewall Misconfiguration / Overly Permissive Rules",
            "description": "Misconfigured rules allow unauthorized access to internal network segments or services.",
            "severity": "Critical",
            "countermeasures": [
                "Apply default-deny policy for all inbound traffic",
                "Regularly audit firewall rules and remove unused ones",
                "Use Infrastructure as Code (IaC) to manage firewall rules",
                "Implement network segmentation and micro-segmentation",
                "Run automated compliance checks (AWS Config, Azure Policy)",
            ],
            "cwe_ids": ["CWE-284", "CWE-269"],
        },
    ],

    "cdn": [
        {
            "stride_category": "T",
            "threat_name": "CDN Cache Poisoning",
            "description": "Attacker manipulates cached responses served to all users by poisoning the CDN cache with malicious content.",
            "severity": "High",
            "countermeasures": [
                "Use unique, unambiguous cache keys",
                "Validate Host and X-Forwarded-Host headers at origin",
                "Implement response integrity checking",
                "Set Vary headers correctly",
                "Monitor CDN cache for unexpected content changes",
            ],
            "cwe_ids": ["CWE-441", "CWE-345"],
        },
        {
            "stride_category": "I",
            "threat_name": "Sensitive Data Cached at Edge Nodes",
            "description": "Authentication tokens, personal data, or other sensitive content is inadvertently cached at CDN edge locations.",
            "severity": "High",
            "countermeasures": [
                "Set Cache-Control: no-store for all authenticated/sensitive responses",
                "Configure CDN to bypass cache for authenticated requests",
                "Audit CDN caching rules regularly",
                "Use private CDN distributions for authenticated content",
            ],
            "cwe_ids": ["CWE-524"],
        },
    ],

    "message_queue": [
        {
            "stride_category": "T",
            "threat_name": "Message Injection / Payload Tampering",
            "description": "Attacker publishes malicious or malformed messages to the queue, causing downstream consumers to process harmful data.",
            "severity": "High",
            "countermeasures": [
                "Authenticate all message producers (IAM roles, mTLS)",
                "Validate and sanitize message payloads at consumer level",
                "Sign messages with HMAC to verify integrity",
                "Implement dead-letter queues with alerting for malformed messages",
            ],
            "cwe_ids": ["CWE-20", "CWE-345"],
        },
        {
            "stride_category": "I",
            "threat_name": "Message Interception / Eavesdropping",
            "description": "Sensitive data in messages is intercepted by unauthorized parties who gain access to the queue.",
            "severity": "High",
            "countermeasures": [
                "Encrypt messages in transit (TLS) and at rest",
                "Use envelope encryption for message payloads",
                "Restrict queue access with fine-grained IAM policies",
                "Avoid placing PII directly in message payloads; use references",
            ],
            "cwe_ids": ["CWE-319", "CWE-312"],
        },
        {
            "stride_category": "D",
            "threat_name": "Queue Flooding / Message Bomb",
            "description": "Attacker floods the queue with massive numbers of messages, starving legitimate consumers and exhausting storage.",
            "severity": "Medium",
            "countermeasures": [
                "Set message throughput limits per producer",
                "Implement consumer auto-scaling based on queue depth",
                "Set queue size limits with backpressure mechanisms",
                "Monitor queue depth and set CloudWatch/alert thresholds",
            ],
            "cwe_ids": ["CWE-400", "CWE-770"],
        },
    ],

    "cloud_service": [
        {
            "stride_category": "E",
            "threat_name": "Overprivileged IAM Roles / Privilege Escalation",
            "description": "Cloud functions or services with excessive permissions allow attackers to escalate privileges and access other cloud resources.",
            "severity": "Critical",
            "countermeasures": [
                "Apply principle of least privilege to all IAM roles",
                "Use IAM permission boundaries",
                "Regularly review and audit IAM policies",
                "Enable AWS CloudTrail / Azure Monitor for all API calls",
                "Use IAM Access Analyzer to detect overpermissive policies",
            ],
            "cwe_ids": ["CWE-269", "CWE-732"],
        },
        {
            "stride_category": "I",
            "threat_name": "Cloud Function Environment Variable Exposure",
            "description": "Secrets, API keys, or connection strings stored in environment variables are exposed through logs, errors, or metadata endpoints.",
            "severity": "High",
            "countermeasures": [
                "Use secrets management services (AWS Secrets Manager, Azure Key Vault)",
                "Never log environment variables",
                "Block access to metadata endpoints from function code",
                "Scan IaC templates for hardcoded secrets",
            ],
            "cwe_ids": ["CWE-532", "CWE-312"],
        },
        {
            "stride_category": "T",
            "threat_name": "Event Injection via Untrusted Triggers",
            "description": "Serverless functions triggered by external events (S3 uploads, API calls, emails) process malicious payloads without validation.",
            "severity": "High",
            "countermeasures": [
                "Validate all event inputs regardless of source",
                "Whitelist trusted event sources",
                "Use sandboxed execution environments",
                "Implement input schema validation at the function entry point",
            ],
            "cwe_ids": ["CWE-20", "CWE-94"],
        },
    ],

    "mobile_app": [
        {
            "stride_category": "S",
            "threat_name": "Reverse Engineering / API Key Extraction",
            "description": "Attacker decompiles the mobile application to extract hardcoded API keys, endpoints, or cryptographic secrets.",
            "severity": "High",
            "countermeasures": [
                "Never hardcode secrets in the mobile app binary",
                "Use certificate pinning to prevent MITM",
                "Implement code obfuscation (ProGuard, R8, DexGuard)",
                "Use secure enclaves for sensitive key storage (Android Keystore, iOS Secure Enclave)",
                "Validate app integrity with SafetyNet / App Attest",
            ],
            "cwe_ids": ["CWE-312", "CWE-295"],
        },
        {
            "stride_category": "I",
            "threat_name": "Insecure Local Data Storage",
            "description": "Sensitive user data (tokens, PII, credentials) is stored in plaintext in SharedPreferences, local databases, or logs.",
            "severity": "High",
            "countermeasures": [
                "Encrypt all sensitive data stored locally",
                "Use platform-provided secure storage APIs",
                "Implement automatic logout and token expiry",
                "Do not log sensitive information",
                "Clear sensitive data on app backgrounding",
            ],
            "cwe_ids": ["CWE-312", "CWE-922"],
        },
    ],

    "external_service": [
        {
            "stride_category": "T",
            "threat_name": "Supply Chain / Third-Party Service Compromise",
            "description": "A compromised third-party service returns malicious responses that are processed without validation, affecting the system.",
            "severity": "High",
            "countermeasures": [
                "Validate all responses from external services",
                "Implement defensive parsing for external data",
                "Monitor third-party service status and anomalies",
                "Use circuit breakers to isolate failures",
                "Prefer services with published SLAs and security certifications",
            ],
            "cwe_ids": ["CWE-494", "CWE-20"],
        },
        {
            "stride_category": "I",
            "threat_name": "Sensitive Data Sent to External Services",
            "description": "Internal or user data is inadvertently sent to third-party services (analytics, logging, error tracking) without appropriate masking.",
            "severity": "Medium",
            "countermeasures": [
                "Audit data sent to all third-party integrations",
                "Mask or anonymize PII before sending to external services",
                "Review DPA (Data Processing Agreements) with vendors",
                "Use data minimization principles",
            ],
            "cwe_ids": ["CWE-359"],
        },
        {
            "stride_category": "D",
            "threat_name": "Dependency on Unavailable External Service",
            "description": "System availability depends on an external service with no fallback, creating a single point of failure.",
            "severity": "Medium",
            "countermeasures": [
                "Implement circuit breakers with fallback behavior",
                "Define and test timeout and retry policies",
                "Cache external service responses where appropriate",
                "Design graceful degradation when external services are unavailable",
            ],
            "cwe_ids": ["CWE-400"],
        },
    ],
}


def get_threats_for_components(component_types: List[str]) -> Dict[str, List[dict]]:
    """
    Return all threats for a given list of component types.
    Includes only threats relevant to the detected components.
    """
    result = {}
    for ctype in component_types:
        if ctype in COMPONENT_THREATS:
            result[ctype] = COMPONENT_THREATS[ctype]
    return result


def get_stride_summary(threats_by_component: Dict[str, List[dict]]) -> Dict[str, List[str]]:
    """
    Return a STRIDE-grouped summary: category -> list of threat names.
    """
    summary = {cat: [] for cat in STRIDE}
    for component, threats in threats_by_component.items():
        for t in threats:
            cat = t["stride_category"]
            entry = f"[{component}] {t['threat_name']}"
            if entry not in summary[cat]:
                summary[cat].append(entry)
    return summary


def get_severity_counts(threats_by_component: Dict[str, List[dict]]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for threats in threats_by_component.values():
        for t in threats:
            severity = t.get("severity", "Low")
            counts[severity] = counts.get(severity, 0) + 1
    return counts
