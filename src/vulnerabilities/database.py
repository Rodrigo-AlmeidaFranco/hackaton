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


# ── v2 threat templates (shared across cloud-specific classes) ─────────────────

_COMPUTE_THREATS = [
    {"stride_category": "T", "threat_name": "Code / Command Injection",
     "description": "Attacker injects malicious code through unvalidated inputs processed by the compute resource.",
     "severity": "Critical",
     "countermeasures": ["Validate and sanitize all user inputs", "Run with least-privilege OS user",
                         "Use WAF to detect injection patterns", "Enable runtime security (Falco, GuardDuty)"],
     "cwe_ids": ["CWE-78", "CWE-94"]},
    {"stride_category": "I", "threat_name": "Instance Metadata / Env Variable Exposure",
     "description": "Secrets or tokens stored as environment variables or accessible via metadata endpoints (SSRF → IMDSv1).",
     "severity": "High",
     "countermeasures": ["Use IMDSv2 on EC2 / enforce metadata protection", "Store secrets in Secrets Manager / Key Vault",
                         "Never log environment variables", "Block metadata endpoint from application code"],
     "cwe_ids": ["CWE-312", "CWE-532"]},
    {"stride_category": "D", "threat_name": "Resource Exhaustion / Compute DoS",
     "description": "Attacker exploits unbounded resource consumption (CPU, memory, disk) to render the instance unavailable.",
     "severity": "High",
     "countermeasures": ["Implement resource quotas and limits", "Enable auto-scaling",
                         "Apply rate limiting at API and network layers", "Use CDN / DDoS protection upstream"],
     "cwe_ids": ["CWE-400", "CWE-770"]},
    {"stride_category": "E", "threat_name": "RCE via Dependency Vulnerabilities",
     "description": "Outdated libraries with known CVEs allow arbitrary code execution and privilege escalation.",
     "severity": "Critical",
     "countermeasures": ["Maintain SBOM and automate dependency scanning (Dependabot, Snyk)",
                         "Apply security patches promptly", "Use minimal base images", "Enable runtime protection"],
     "cwe_ids": ["CWE-1104", "CWE-502"]},
]

_LAMBDA_THREATS = [
    {"stride_category": "T", "threat_name": "Event Injection via Untrusted Triggers",
     "description": "Serverless functions triggered by external events process malicious payloads without validation.",
     "severity": "High",
     "countermeasures": ["Validate all event inputs regardless of source", "Whitelist trusted event source ARNs",
                         "Use input schema validation at function entry point", "Implement dead-letter queues"],
     "cwe_ids": ["CWE-20", "CWE-94"]},
    {"stride_category": "I", "threat_name": "Environment Variable / Secrets Exposure",
     "description": "API keys or credentials in Lambda env vars are exposed through CloudWatch logs or error responses.",
     "severity": "High",
     "countermeasures": ["Use Secrets Manager / SSM Parameter Store instead of env vars",
                         "Enable KMS encryption for Lambda env vars", "Redact sensitive values from logs"],
     "cwe_ids": ["CWE-312", "CWE-532"]},
    {"stride_category": "E", "threat_name": "Overprivileged Lambda / Function Execution Role",
     "description": "Functions with excessive IAM permissions allow attackers to pivot to other cloud services.",
     "severity": "Critical",
     "countermeasures": ["Apply least privilege to execution roles", "Use resource-based conditions in IAM",
                         "Enable AWS Config rules to detect overpermissive roles", "Review IAM Access Advisor"],
     "cwe_ids": ["CWE-269", "CWE-732"]},
    {"stride_category": "D", "threat_name": "Concurrency Exhaustion",
     "description": "Attacker floods the function with requests consuming all concurrency, throttling legitimate users.",
     "severity": "Medium",
     "countermeasures": ["Set reserved concurrency limits", "Use SQS with backpressure for async invocations",
                         "Monitor concurrency metrics with alarms"],
     "cwe_ids": ["CWE-400"]},
]

_CONTAINER_THREATS = [
    {"stride_category": "E", "threat_name": "Container Escape / Host Privilege Escalation",
     "description": "Attacker exploits kernel vulnerabilities or privileged mode to escape the container and access the host.",
     "severity": "Critical",
     "countermeasures": ["Never run containers in privileged mode", "Use seccomp and AppArmor/SELinux profiles",
                         "Run as non-root user", "Enable runtime security (Falco, Aqua, Sysdig)"],
     "cwe_ids": ["CWE-269", "CWE-284"]},
    {"stride_category": "T", "threat_name": "Container Image Poisoning / Supply Chain",
     "description": "Compromised registry or CI/CD pipeline injects malicious code into deployed images.",
     "severity": "High",
     "countermeasures": ["Sign images with Cosign / Notary", "Scan images in CI/CD (Trivy, Snyk)",
                         "Pull only from trusted private registries", "Use admission controllers (OPA, Kyverno)"],
     "cwe_ids": ["CWE-494"]},
    {"stride_category": "I", "threat_name": "Secrets in Container Environment / Image Layers",
     "description": "Credentials baked into images or passed as env vars are exposed.",
     "severity": "High",
     "countermeasures": ["Use Kubernetes Secrets / Secrets Manager / Key Vault", "Never embed secrets in Dockerfiles",
                         "Scan images for secrets (truffleHog)", "Use workload identity for short-lived credentials"],
     "cwe_ids": ["CWE-312", "CWE-798"]},
    {"stride_category": "D", "threat_name": "Container Resource Exhaustion (noisy neighbor)",
     "description": "Compromised containers consume excessive CPU/memory, affecting co-located workloads.",
     "severity": "Medium",
     "countermeasures": ["Set CPU and memory limits on all containers", "Enable pod disruption budgets",
                         "Use namespace resource quotas", "Monitor with Prometheus / Container Insights"],
     "cwe_ids": ["CWE-400"]},
]

_DATABASE_THREATS_V2 = [
    {"stride_category": "T", "threat_name": "SQL / NoSQL Injection",
     "description": "Malicious queries manipulate, delete, or exfiltrate data through unvalidated inputs.",
     "severity": "Critical",
     "countermeasures": ["Use ORM with parameterized queries exclusively", "Apply least privilege DB permissions",
                         "Deploy a database firewall / proxy", "Run regular DAST scans"],
     "cwe_ids": ["CWE-89", "CWE-943"]},
    {"stride_category": "I", "threat_name": "Unauthorized Data Access / Data Breach",
     "description": "Sensitive data accessed via missing access controls, unencrypted storage, or backup exposure.",
     "severity": "Critical",
     "countermeasures": ["Encrypt at rest (AES-256) and in transit (TLS 1.3)", "Implement row/column-level security",
                         "Use Secrets Manager for DB credentials", "Disable public network access"],
     "cwe_ids": ["CWE-312", "CWE-359"]},
    {"stride_category": "D", "threat_name": "Database Resource Exhaustion",
     "description": "Expensive or unbounded queries exhaust CPU, connections, or storage.",
     "severity": "High",
     "countermeasures": ["Set query timeouts and connection pool limits", "Monitor slow queries",
                         "Use read replicas for read-heavy workloads", "Deploy a caching layer"],
     "cwe_ids": ["CWE-400"]},
    {"stride_category": "E", "threat_name": "Database Privilege Escalation",
     "description": "Attacker gains higher privileges through stored procedure exploitation or role mismanagement.",
     "severity": "High",
     "countermeasures": ["Apply least privilege to all DB accounts", "Disable dangerous stored procedures",
                         "Audit and alert on privilege changes", "Use separate accounts for app vs admin"],
     "cwe_ids": ["CWE-269"]},
]

_ANALYTICS_EXTRA = [
    {"stride_category": "I", "threat_name": "Analytics Data Exfiltration",
     "description": "Large-scale data export from analytics/warehouse systems exposes sensitive business or user data.",
     "severity": "Critical",
     "countermeasures": ["Implement data export controls and quotas", "Alert on large query result exports",
                         "Apply column-level encryption for PII", "Use VPC endpoints / private connectivity"],
     "cwe_ids": ["CWE-359", "CWE-200"]},
]

_STORAGE_THREATS = [
    {"stride_category": "I", "threat_name": "Public Bucket / Storage Misconfiguration",
     "description": "Object storage configured as publicly accessible exposes sensitive files to the internet.",
     "severity": "Critical",
     "countermeasures": ["Block all public access at account level", "Enable S3 Block Public Access / Azure restriction",
                         "Run continuous misconfiguration scanning (AWS Config, Defender for Cloud)",
                         "Encrypt all objects with customer-managed keys"],
     "cwe_ids": ["CWE-284", "CWE-200"]},
    {"stride_category": "T", "threat_name": "Malicious File Upload / Object Poisoning",
     "description": "Attackers upload malicious executables or scripts that are executed by backend services.",
     "severity": "High",
     "countermeasures": ["Validate file types and magic bytes server-side",
                         "Scan uploads for malware (Defender for Storage, Lambda AV)",
                         "Never serve uploads from the same domain", "Restrict presigned URL permissions and TTL"],
     "cwe_ids": ["CWE-434", "CWE-494"]},
    {"stride_category": "S", "threat_name": "Presigned URL / SAS Token Abuse",
     "description": "Leaked or overly permissive presigned URLs / SAS tokens allow unauthorized object access.",
     "severity": "High",
     "countermeasures": ["Use short-lived presigned URLs (< 1 hour TTL)",
                         "Restrict to minimum required operations", "Monitor access logs for anomalies",
                         "Revoke compromised SAS tokens immediately"],
     "cwe_ids": ["CWE-345", "CWE-284"]},
    {"stride_category": "D", "threat_name": "Storage Cost / Capacity Exhaustion",
     "description": "Attacker uploads massive amounts of data, incurring cost and degrading performance.",
     "severity": "Low",
     "countermeasures": ["Implement upload size limits", "Set storage quotas and billing alerts",
                         "Monitor and alert on unusual PUT request volumes"],
     "cwe_ids": ["CWE-400"]},
]

_MQ_THREATS = [
    {"stride_category": "T", "threat_name": "Message Injection / Payload Tampering",
     "description": "Attacker publishes malicious messages causing downstream consumers to process harmful data.",
     "severity": "High",
     "countermeasures": ["Authenticate all producers (IAM roles, mTLS)", "Validate payloads at consumer level",
                         "Sign messages with HMAC", "Implement dead-letter queues with alerting"],
     "cwe_ids": ["CWE-20", "CWE-345"]},
    {"stride_category": "I", "threat_name": "Message Interception / Eavesdropping",
     "description": "Sensitive data in messages intercepted by unauthorized parties.",
     "severity": "High",
     "countermeasures": ["Encrypt messages in transit (TLS) and at rest", "Use envelope encryption",
                         "Restrict queue access with IAM policies", "Avoid PII in payloads; use references"],
     "cwe_ids": ["CWE-319", "CWE-312"]},
    {"stride_category": "D", "threat_name": "Queue Flooding / Message Bomb",
     "description": "Attacker floods the queue, starving legitimate consumers and exhausting storage.",
     "severity": "Medium",
     "countermeasures": ["Set throughput limits per producer", "Implement consumer auto-scaling",
                         "Set queue size limits with backpressure", "Monitor queue depth with alerts"],
     "cwe_ids": ["CWE-400", "CWE-770"]},
    {"stride_category": "R", "threat_name": "Message Origin Non-Repudiation Failure",
     "description": "Without message signing, producers can deny sending specific messages.",
     "severity": "Medium",
     "countermeasures": ["Sign messages with producer private key or HMAC",
                         "Log message metadata in audit trail", "Implement receipts for critical operations"],
     "cwe_ids": ["CWE-778"]},
]

_LB_THREATS = [
    {"stride_category": "S", "threat_name": "SSL Stripping / TLS Downgrade Attack",
     "description": "MITM attacker forces connection to downgrade from HTTPS to HTTP, exposing traffic.",
     "severity": "High",
     "countermeasures": ["Enforce HTTPS-only with HSTS (includeSubDomains, preload)",
                         "Configure minimum TLS 1.2, prefer TLS 1.3", "Disable weak cipher suites",
                         "Use certificate pinning for mobile clients"],
     "cwe_ids": ["CWE-326", "CWE-295"]},
    {"stride_category": "D", "threat_name": "SYN Flood / DDoS via Load Balancer",
     "description": "Attacker exhausts connection table with SYN flood or volumetric attacks.",
     "severity": "High",
     "countermeasures": ["Enable SYN cookies", "Deploy DDoS scrubbing (AWS Shield, Azure DDoS Protection)",
                         "Set aggressive connection timeouts", "Enable auto-scaling for backend targets"],
     "cwe_ids": ["CWE-400"]},
    {"stride_category": "I", "threat_name": "Sensitive Header / Log Leakage",
     "description": "Load balancer access logs contain sensitive headers stored in plain text.",
     "severity": "Medium",
     "countermeasures": ["Mask sensitive headers in access logs", "Restrict log access",
                         "Forward only necessary headers to backends", "Strip internal headers from external requests"],
     "cwe_ids": ["CWE-532"]},
]

_CDN_THREATS_V2 = [
    {"stride_category": "T", "threat_name": "CDN Cache Poisoning",
     "description": "Attacker poisons CDN cache to serve malicious content to all users.",
     "severity": "High",
     "countermeasures": ["Use unique, unambiguous cache keys", "Validate Host header at origin",
                         "Implement SRI for response integrity", "Monitor cache for unexpected changes"],
     "cwe_ids": ["CWE-441", "CWE-345"]},
    {"stride_category": "I", "threat_name": "Sensitive Data Cached at Edge",
     "description": "Auth tokens or PII inadvertently cached at CDN edge locations.",
     "severity": "High",
     "countermeasures": ["Set Cache-Control: no-store for authenticated responses",
                         "Configure CDN to bypass cache for auth requests", "Audit CDN caching rules regularly"],
     "cwe_ids": ["CWE-524"]},
]

_DNS_THREATS = [
    {"stride_category": "S", "threat_name": "DNS Hijacking / Cache Poisoning",
     "description": "Attacker poisons DNS cache or hijacks records to redirect traffic to malicious servers.",
     "severity": "Critical",
     "countermeasures": ["Enable DNSSEC for all hosted zones", "Monitor for unexpected record changes",
                         "Enable Route 53 Transfer Lock / Azure DNS record locks"],
     "cwe_ids": ["CWE-350", "CWE-290"]},
    {"stride_category": "D", "threat_name": "DNS Amplification DDoS",
     "description": "Attacker uses DNS infrastructure as DDoS amplification vector.",
     "severity": "High",
     "countermeasures": ["Use anycast DNS to absorb attacks", "Enable Shield Advanced / Azure DDoS Protection",
                         "Rate limit DNS responses per source IP"],
     "cwe_ids": ["CWE-400"]},
]

_IAM_THREATS = [
    {"stride_category": "E", "threat_name": "Overprivileged IAM Roles / Privilege Escalation",
     "description": "IAM roles with excessive permissions allow attackers to pivot to other cloud resources.",
     "severity": "Critical",
     "countermeasures": ["Apply least privilege to all IAM roles", "Use permission boundaries and SCPs",
                         "Enable IAM Access Analyzer", "Enable CloudTrail / Azure Monitor for IAM API calls",
                         "Rotate access keys and remove unused credentials"],
     "cwe_ids": ["CWE-269", "CWE-732"]},
    {"stride_category": "S", "threat_name": "Credential / Token Theft",
     "description": "Attacker steals IAM access keys or service principal secrets through phishing or SSRF.",
     "severity": "Critical",
     "countermeasures": ["Never store long-term access keys; prefer instance roles / managed identities",
                         "Enable MFA for all human users", "Scan repos for accidental key commits",
                         "Enable GuardDuty / Defender for Cloud to detect credential abuse"],
     "cwe_ids": ["CWE-287", "CWE-522"]},
    {"stride_category": "T", "threat_name": "IAM Policy Tampering",
     "description": "Attacker modifies IAM policies to grant unauthorized access.",
     "severity": "High",
     "countermeasures": ["Enable CloudTrail for all IAM changes", "Use Config rules to detect policy drift",
                         "Require MFA for sensitive IAM operations", "Implement separation of duties"],
     "cwe_ids": ["CWE-269"]},
    {"stride_category": "I", "threat_name": "Secrets / API Keys Exposure",
     "description": "Secrets stored in KMS or credential stores exposed through misconfiguration or excessive access.",
     "severity": "Critical",
     "countermeasures": ["Use Secrets Manager / Key Vault with fine-grained access policies",
                         "Enable automatic secret rotation", "Audit secret access logs for anomalies"],
     "cwe_ids": ["CWE-312", "CWE-798"]},
]

_WAF_THREATS = [
    {"stride_category": "T", "threat_name": "WAF / Firewall Rule Bypass",
     "description": "Attacker uses HTTP smuggling or encoding tricks to bypass firewall rules.",
     "severity": "High",
     "countermeasures": ["Enable OWASP Core Rule Set and update regularly",
                         "Implement deep packet inspection", "Test rules with red team exercises",
                         "Monitor WAF logs and tune rules"],
     "cwe_ids": ["CWE-693"]},
    {"stride_category": "E", "threat_name": "Firewall / NSG Misconfiguration",
     "description": "Overly permissive rules allow unauthorized access to internal services.",
     "severity": "Critical",
     "countermeasures": ["Apply default-deny policy", "Audit rules regularly with automated tools",
                         "Use IaC to manage rules (no manual changes)", "Run automated compliance checks"],
     "cwe_ids": ["CWE-284", "CWE-269"]},
    {"stride_category": "D", "threat_name": "DDoS Bypass / Rate Limit Evasion",
     "description": "Attacker distributes requests to evade firewall rate limiting.",
     "severity": "High",
     "countermeasures": ["Enable adaptive rate limiting based on behavior",
                         "Use IP reputation feeds and geo-blocking", "Deploy upstream DDoS scrubbing"],
     "cwe_ids": ["CWE-770"]},
]

_MONITORING_THREATS = [
    {"stride_category": "R", "threat_name": "Audit Log Tampering / Deletion",
     "description": "Attacker deletes or modifies audit logs to cover tracks after a breach.",
     "severity": "High",
     "countermeasures": ["Enable log integrity validation (CloudTrail log file validation)",
                         "Forward logs to immutable storage (S3 Object Lock, Azure Immutable Blob)",
                         "Alert on any attempts to disable or modify logging"],
     "cwe_ids": ["CWE-778"]},
    {"stride_category": "I", "threat_name": "Sensitive Data Exposure in Logs",
     "description": "Application logs contain PII, credentials, or other sensitive data.",
     "severity": "Medium",
     "countermeasures": ["Implement log scrubbing to redact sensitive patterns",
                         "Restrict access to log streams", "Scan logs for accidental secret exposure"],
     "cwe_ids": ["CWE-532", "CWE-359"]},
    {"stride_category": "T", "threat_name": "Metric / Alert Suppression",
     "description": "Attacker disables monitoring alerts to prevent detection of ongoing attacks.",
     "severity": "High",
     "countermeasures": ["Alert on monitoring service disruption itself",
                         "Separate monitoring infrastructure from application infrastructure",
                         "Require MFA for monitoring admin operations"],
     "cwe_ids": ["CWE-693"]},
]

_API_GW_THREATS = [
    {"stride_category": "S", "threat_name": "API Key / JWT Token Forgery",
     "description": "Attacker uses stolen or forged API keys / JWT tokens to authenticate as a legitimate client.",
     "severity": "High",
     "countermeasures": ["Rotate API keys regularly", "Use short-lived JWTs with proper signature validation",
                         "Implement OAuth 2.0 with scopes", "Store API keys in secrets management"],
     "cwe_ids": ["CWE-345", "CWE-347"]},
    {"stride_category": "T", "threat_name": "Request Tampering / Parameter Pollution",
     "description": "Attacker modifies API parameters to bypass business logic or access unauthorized resources.",
     "severity": "High",
     "countermeasures": ["Validate and whitelist all parameters at the gateway",
                         "Implement strict JSON Schema / OpenAPI validation",
                         "Sign requests with HMAC for integrity"],
     "cwe_ids": ["CWE-235", "CWE-915"]},
    {"stride_category": "D", "threat_name": "API Abuse / Rate Limit Bypass",
     "description": "Attacker bypasses rate limits for scraping, brute-force, or resource exhaustion.",
     "severity": "Medium",
     "countermeasures": ["Enforce per-client rate limits", "Implement adaptive rate limiting",
                         "Apply quotas per API key / subscription plan"],
     "cwe_ids": ["CWE-770"]},
    {"stride_category": "I", "threat_name": "API Schema / Documentation Exposure",
     "description": "Public API docs expose endpoint structure, auth mechanisms, and data models.",
     "severity": "Low",
     "countermeasures": ["Restrict API docs to authenticated users",
                         "Disable auto-generated docs in production if not needed"],
     "cwe_ids": ["CWE-200"]},
]

_MLAI_THREATS = [
    {"stride_category": "T", "threat_name": "Model / Training Data Poisoning",
     "description": "Attacker injects adversarial samples into training data or modifies model weights.",
     "severity": "High",
     "countermeasures": ["Validate and sanitize training data sources", "Implement data provenance tracking",
                         "Verify model integrity before deployment", "Monitor output distributions in production"],
     "cwe_ids": ["CWE-20", "CWE-494"]},
    {"stride_category": "I", "threat_name": "Training Data / Model Theft",
     "description": "Attacker exfiltrates proprietary training datasets or model weights.",
     "severity": "High",
     "countermeasures": ["Apply strict access controls to model artifacts", "Rate limit inference API calls",
                         "Use differential privacy for sensitive training data", "Encrypt model weights"],
     "cwe_ids": ["CWE-312", "CWE-200"]},
    {"stride_category": "E", "threat_name": "Excessive ML Service Permissions",
     "description": "ML service roles with broad permissions allow attackers to access training data after compromise.",
     "severity": "High",
     "countermeasures": ["Apply least privilege to ML service roles", "Isolate ML workloads in dedicated VPCs",
                         "Use managed identities instead of long-term credentials"],
     "cwe_ids": ["CWE-269"]},
    {"stride_category": "D", "threat_name": "Adversarial Input / Inference DoS",
     "description": "Crafted inputs cause expensive inference computations, exhausting GPU/CPU resources.",
     "severity": "Medium",
     "countermeasures": ["Set inference timeout and cost limits", "Apply rate limiting on inference endpoints",
                         "Enable auto-scaling for inference infrastructure"],
     "cwe_ids": ["CWE-400"]},
]

_VPC_THREATS = [
    {"stride_category": "E", "threat_name": "Network Segmentation Misconfiguration",
     "description": "Overly permissive security groups or NSG rules allow lateral movement.",
     "severity": "Critical",
     "countermeasures": ["Apply default-deny in all security groups / NSG rules",
                         "Use micro-segmentation between services",
                         "Audit network rules regularly", "Enable VPC Flow Logs / NSG Flow Logs"],
     "cwe_ids": ["CWE-284"]},
    {"stride_category": "T", "threat_name": "Lateral Movement via Misconfigured Network Paths",
     "description": "Attacker moves laterally by exploiting overly permissive routing or peering configurations.",
     "severity": "High",
     "countermeasures": ["Implement network access controls between peered VPCs",
                         "Use private endpoints instead of public internet routes",
                         "Enable network anomaly detection (GuardDuty, Defender)"],
     "cwe_ids": ["CWE-285"]},
    {"stride_category": "I", "threat_name": "Unencrypted Internal Traffic",
     "description": "Traffic between internal services traverses unencrypted, exposing sensitive data.",
     "severity": "High",
     "countermeasures": ["Enforce TLS for all internal service-to-service communication",
                         "Use service mesh (Istio, Linkerd) for mTLS", "Audit and eliminate plain HTTP"],
     "cwe_ids": ["CWE-319"]},
]

_DEVOPS_THREATS = [
    {"stride_category": "T", "threat_name": "CI/CD Pipeline Tampering / Supply Chain",
     "description": "Attacker modifies pipeline definitions or injects malicious steps to deploy backdoored artifacts.",
     "severity": "Critical",
     "countermeasures": ["Require code review for pipeline definition changes",
                         "Pin dependencies to specific versions/hashes",
                         "Sign and verify all build artifacts", "Use ephemeral build environments"],
     "cwe_ids": ["CWE-494", "CWE-20"]},
    {"stride_category": "I", "threat_name": "Secrets in Pipeline / Workflow Definitions",
     "description": "Credentials hardcoded in pipeline configs are exposed in version control or logs.",
     "severity": "High",
     "countermeasures": ["Use pipeline secret stores (GitHub Secrets, Azure DevOps Variable Groups)",
                         "Never hardcode credentials in pipeline YAML", "Enable secret scanning in repositories"],
     "cwe_ids": ["CWE-798", "CWE-312"]},
    {"stride_category": "E", "threat_name": "Pipeline Service Account Overprovisioning",
     "description": "CI/CD service accounts with excessive permissions allow full cloud access after pipeline compromise.",
     "severity": "Critical",
     "countermeasures": ["Use OIDC federated identity instead of long-term keys",
                         "Scope pipeline permissions to specific resources",
                         "Separate deployment and testing accounts"],
     "cwe_ids": ["CWE-269"]},
]

_BACKUP_THREATS = [
    {"stride_category": "T", "threat_name": "Backup Tampering / Ransomware",
     "description": "Attacker modifies or encrypts backups, rendering disaster recovery impossible.",
     "severity": "Critical",
     "countermeasures": ["Enable immutable backup storage (Object Lock, Vault Lock)",
                         "Store backups in a separate account with restricted access",
                         "Test backup restoration regularly", "Require MFA for backup deletion"],
     "cwe_ids": ["CWE-693"]},
    {"stride_category": "I", "threat_name": "Sensitive Data Exposure via Backup",
     "description": "Unencrypted backups containing sensitive data accessed by unauthorized parties.",
     "severity": "High",
     "countermeasures": ["Encrypt all backups with customer-managed keys",
                         "Restrict backup access to dedicated admins", "Monitor backup access logs"],
     "cwe_ids": ["CWE-312"]},
]

_RESOURCE_GROUP_THREATS = [
    {"stride_category": "E", "threat_name": "Resource Boundary Misconfiguration",
     "description": "Overly permissive resource group allows unauthorized cross-resource access.",
     "severity": "High",
     "countermeasures": ["Apply RBAC at resource group level with minimum permissions",
                         "Use resource locks to prevent accidental deletion",
                         "Audit resource group memberships regularly",
                         "Enable policy enforcement (Azure Policy, AWS SCP)"],
     "cwe_ids": ["CWE-284"]},
    {"stride_category": "I", "threat_name": "Resource Metadata / Tag Exposure",
     "description": "Resource tags or metadata containing sensitive info are publicly accessible.",
     "severity": "Low",
     "countermeasures": ["Establish tagging policies excluding sensitive values",
                         "Restrict access to resource metadata APIs", "Audit tags for sensitive content"],
     "cwe_ids": ["CWE-200"]},
]

_EXTERNAL_THREATS = [
    {"stride_category": "T", "threat_name": "Supply Chain / Third-Party Service Compromise",
     "description": "A compromised third-party service returns malicious responses processed without validation.",
     "severity": "High",
     "countermeasures": ["Validate all responses from external services",
                         "Implement defensive parsing", "Use circuit breakers to isolate failures"],
     "cwe_ids": ["CWE-494", "CWE-20"]},
    {"stride_category": "I", "threat_name": "Sensitive Data Sent to External Services",
     "description": "Internal data inadvertently sent to third-party services without masking.",
     "severity": "Medium",
     "countermeasures": ["Audit data sent to all integrations", "Mask PII before sending externally",
                         "Review Data Processing Agreements with vendors"],
     "cwe_ids": ["CWE-359"]},
    {"stride_category": "D", "threat_name": "Dependency on Unavailable External Service",
     "description": "System depends on an external service with no fallback, creating a single point of failure.",
     "severity": "Medium",
     "countermeasures": ["Implement circuit breakers with fallback", "Define timeout and retry policies",
                         "Design graceful degradation when external services are unavailable"],
     "cwe_ids": ["CWE-400"]},
]

_CACHE_THREATS_V2 = [
    {"stride_category": "I", "threat_name": "Cache Poisoning / Sensitive Data in Cache",
     "description": "Attacker accesses cached sensitive data of other users or poisons cached responses.",
     "severity": "High",
     "countermeasures": ["Never cache user-specific sensitive data", "Validate cache keys",
                         "Encrypt data in cache (ElastiCache encryption in-transit/at-rest)",
                         "Isolate cache per tenant in multi-tenant systems"],
     "cwe_ids": ["CWE-524", "CWE-441"]},
    {"stride_category": "T", "threat_name": "Cache Key Injection / Collision",
     "description": "Attacker manipulates cache keys to serve tampered responses.",
     "severity": "Medium",
     "countermeasures": ["Sanitize inputs used in cache key construction", "Use namespaced cache keys",
                         "Set appropriate TTLs per data sensitivity"],
     "cwe_ids": ["CWE-345"]},
    {"stride_category": "D", "threat_name": "Cache Stampede / Thundering Herd",
     "description": "Simultaneous cache misses cause all requests to hammer the backend simultaneously.",
     "severity": "Medium",
     "countermeasures": ["Implement cache locking for popular keys", "Use probabilistic early expiration",
                         "Warm up cache before deploying new versions"],
     "cwe_ids": ["CWE-400"]},
]

_ANALYTICS_DB_THREATS = _DATABASE_THREATS_V2 + _ANALYTICS_EXTRA

# ── v2 COMPONENT_THREATS additions (111 cloud-specific classes) ────────────────

_V2_ENTRIES = {
    # ── Generic ───────────────────────────────────────────────────────────────
    "api":                                                    _API_GW_THREATS,
    "user":                                                   [
        {"stride_category": "S", "threat_name": "Identity Spoofing / Credential Theft",
         "description": "Attacker impersonates a legitimate user via phishing, brute-force, or credential stuffing.",
         "severity": "High",
         "countermeasures": ["Enforce MFA", "Implement account lockout after N failed attempts",
                             "Use bcrypt/argon2 for password hashing", "Monitor suspicious login patterns"],
         "cwe_ids": ["CWE-287", "CWE-521"]},
        {"stride_category": "R", "threat_name": "Repudiation of User Actions",
         "description": "User denies having performed an action with no audit trail.",
         "severity": "Medium",
         "countermeasures": ["Implement tamper-proof audit logging", "Use digital signatures for critical ops",
                             "Store logs in immutable storage"],
         "cwe_ids": ["CWE-778"]},
        {"stride_category": "E", "threat_name": "Privilege Escalation via Session Hijacking",
         "description": "Attacker steals a session token (XSS, MITM) and gains elevated access.",
         "severity": "High",
         "countermeasures": ["Set HttpOnly and Secure flags on cookies", "Use SameSite=Strict",
                             "Implement short session timeouts", "Regenerate session ID after privilege changes"],
         "cwe_ids": ["CWE-384", "CWE-613"]},
    ],
    "developer_portal":                                       _API_GW_THREATS,
    "sass_services":                                          _EXTERNAL_THREATS,
    "sei/sip":                                                _EXTERNAL_THREATS,
    "solr":                                                   _DATABASE_THREATS_V2,
    "resource_group":                                         _RESOURCE_GROUP_THREATS,
    "logic_apps":                                             _DEVOPS_THREATS,
    "microsoft_entra":                                        _IAM_THREATS,

    # ── AWS Compute ───────────────────────────────────────────────────────────
    "aws_amazon_ec2":                                         _COMPUTE_THREATS,
    "aws_ec2_instance":                                       _COMPUTE_THREATS,
    "aws_ec2_instances":                                      _COMPUTE_THREATS,
    "aws_amazon_ec2_auto_scaling":                            _COMPUTE_THREATS,
    "aws_auto_scaling":                                       _COMPUTE_THREATS,
    "aws_autoscaling":                                        _COMPUTE_THREATS,

    # ── AWS Lambda / Serverless ───────────────────────────────────────────────
    "aws_lambda":                                             _LAMBDA_THREATS,
    "aws_lambda_lambda_function":                             _LAMBDA_THREATS,

    # ── AWS Containers ────────────────────────────────────────────────────────
    "aws_amazon_elastic_container_service":                   _CONTAINER_THREATS,
    "aws_elastic_container_service_service":                  _CONTAINER_THREATS,
    "aws_elastic_container_service_container_2":              _CONTAINER_THREATS,
    "aws_amazon_elastic_kubernetes_service":                  _CONTAINER_THREATS,

    # ── AWS Databases ─────────────────────────────────────────────────────────
    "aws_amazon_rds":                                         _DATABASE_THREATS_V2,
    "aws_rds":                                                _DATABASE_THREATS_V2,
    "aws_aurora_amazon_rds_instance":                         _DATABASE_THREATS_V2,
    "aws_amazon_dynamodb":                                    _DATABASE_THREATS_V2,
    "aws_dynamodb_table":                                     _DATABASE_THREATS_V2,
    "aws_amazon_redshift":                                    _ANALYTICS_DB_THREATS,

    # ── AWS Storage ───────────────────────────────────────────────────────────
    "aws_amazon_simple_storage_service":                      _STORAGE_THREATS,
    "aws_simple_storage_service_bucket":                      _STORAGE_THREATS,
    "aws_simple_storage_service_bucket_with_objects":         _STORAGE_THREATS,
    "aws_simple_storage_service_object":                      _STORAGE_THREATS,
    "aws_simple_storage_service_s3_standard":                 _STORAGE_THREATS,
    "aws_amazon_elastic_block_store":                         _STORAGE_THREATS,
    "aws_elastic_block_store_volume":                         _STORAGE_THREATS,
    "aws_elactic_file_system(nfs)_multi-az":                  _STORAGE_THREATS,

    # ── AWS Messaging ─────────────────────────────────────────────────────────
    "aws_amazon_simple_queue_service":                        _MQ_THREATS,
    "aws_simple_queue_service_queue":                         _MQ_THREATS,
    "aws_amazon_simple_notification_service":                 _MQ_THREATS,
    "aws_simple_notification_service_topic":                  _MQ_THREATS,
    "aws_simple_email_service":                               _MQ_THREATS,

    # ── AWS Load Balancers ────────────────────────────────────────────────────
    "aws_elastic_load_balancing":                             _LB_THREATS,
    "aws_elastic_load_balancing_application_load_balancer":   _LB_THREATS,
    "aws_elastic_load_balancing_network_load_balancer":       _LB_THREATS,
    "aws_application_load_balancer":                          _LB_THREATS,

    # ── AWS CDN ───────────────────────────────────────────────────────────────
    "aws_amazon_cloudfront":                                  _CDN_THREATS_V2,
    "aws_cloudfront":                                         _CDN_THREATS_V2,

    # ── AWS DNS ───────────────────────────────────────────────────────────────
    "aws_amazon_route_53":                                    _DNS_THREATS,
    "aws_route_53_hosted_zone":                               _DNS_THREATS,

    # ── AWS IAM / Security ────────────────────────────────────────────────────
    "aws_identity_and_access_management":                     _IAM_THREATS,
    "aws_identity_access_management_role":                    _IAM_THREATS,
    "aws_key_management_service":                             _IAM_THREATS,

    # ── AWS Networking ────────────────────────────────────────────────────────
    "aws_amazon_virtual_private_cloud":                       _VPC_THREATS,
    "aws_virtual_private_cloud":                              _VPC_THREATS,
    "aws_vpc_virtual_private_cloud_vpc":                      _VPC_THREATS,
    "aws_private_subnet":                                     _VPC_THREATS,
    "aws_public_subnet":                                      _VPC_THREATS,
    "aws_region":                                             _VPC_THREATS,
    "aws_cloud":                                              _VPC_THREATS,

    # ── AWS WAF ───────────────────────────────────────────────────────────────
    "aws_waf":                                                _WAF_THREATS,

    # ── AWS Monitoring ────────────────────────────────────────────────────────
    "aws_amazon_cloudwatch":                                  _MONITORING_THREATS,
    "aws_cloudwatch":                                         _MONITORING_THREATS,
    "aws_cloud_trail":                                        _MONITORING_THREATS,

    # ── AWS API Gateway ───────────────────────────────────────────────────────
    "aws_amazon_api_gateway":                                 _API_GW_THREATS,

    # ── AWS Cache ─────────────────────────────────────────────────────────────
    "aws_amazon_elasticache":                                 _CACHE_THREATS_V2,
    "aws_elasticache":                                        _CACHE_THREATS_V2,

    # ── AWS IaC / DevOps ─────────────────────────────────────────────────────
    "aws_cloudformation":                                     _DEVOPS_THREATS,
    "aws_cloudformation_template":                            _DEVOPS_THREATS,

    # ── AWS Backup ────────────────────────────────────────────────────────────
    "aws_backup":                                             _BACKUP_THREATS,

    # ── Azure Compute ─────────────────────────────────────────────────────────
    "azure_virtual_machine":                                  _COMPUTE_THREATS,
    "azure_vm_scale_sets":                                    _COMPUTE_THREATS,
    "azure_app_services":                                     _COMPUTE_THREATS,
    "azure_container_instances":                              _CONTAINER_THREATS,
    "azure_kubernetes_services":                              _CONTAINER_THREATS,
    "azure_function_apps":                                    _LAMBDA_THREATS,
    "azure_databricks":                                       _MLAI_THREATS,

    # ── Azure Databases ───────────────────────────────────────────────────────
    "azure_sql":                                              _DATABASE_THREATS_V2,
    "azure_sql_database":                                     _DATABASE_THREATS_V2,
    "azure_sql_server":                                       _DATABASE_THREATS_V2,
    "azure_sql_managed_instance":                             _DATABASE_THREATS_V2,
    "azure_cosmos_db":                                        _DATABASE_THREATS_V2,
    "azure_synapse_analytics":                                _ANALYTICS_DB_THREATS,

    # ── Azure Storage ─────────────────────────────────────────────────────────
    "azure_storage_accounts":                                 _STORAGE_THREATS,

    # ── Azure Messaging ───────────────────────────────────────────────────────
    "azure_event_hubs":                                       _MQ_THREATS,

    # ── Azure Load Balancer ───────────────────────────────────────────────────
    "azure_load_balancers":                                   _LB_THREATS,

    # ── Azure Networking ──────────────────────────────────────────────────────
    "azure_virtual_networks":                                 _VPC_THREATS,
    "azure_network_security_groups":                          _WAF_THREATS,
    "azure_firewalls":                                        _WAF_THREATS,

    # ── Azure IAM / Security ──────────────────────────────────────────────────
    "azure_key_vaults":                                       _IAM_THREATS,

    # ── Azure Monitoring ──────────────────────────────────────────────────────
    "azure_monitor":                                          _MONITORING_THREATS,
    "azure_application_insights":                             _MONITORING_THREATS,

    # ── Azure API / Integration ───────────────────────────────────────────────
    "azure_api_management_services":                          _API_GW_THREATS,
    "azure_logic_apps":                                       _DEVOPS_THREATS,
    "azure_data_factories":                                   _DEVOPS_THREATS,

    # ── Azure ML / AI ─────────────────────────────────────────────────────────
    "azure_machine_learning":                                 _MLAI_THREATS,
    "azure_machine_learning_studio_workspaces":               _MLAI_THREATS,
    "azure_openai":                                           _MLAI_THREATS,

    # ── Azure DevOps ──────────────────────────────────────────────────────────
    "azure_devops":                                           _DEVOPS_THREATS,

    # ── Azure Resource Management ─────────────────────────────────────────────
    "azure_resource_groups":                                  _RESOURCE_GROUP_THREATS,
    "azure_services":                                         _RESOURCE_GROUP_THREATS,

    # ── GCP Compute ───────────────────────────────────────────────────────────
    "gcp_compute_engine":                                     _COMPUTE_THREATS,
    "gcp_cloud_run":                                          _CONTAINER_THREATS,
    "gcp_google_kubernetes_engine":                           _CONTAINER_THREATS,
    "gcp_cloud_functions":                                    _LAMBDA_THREATS,

    # ── GCP Databases ─────────────────────────────────────────────────────────
    "gcp_cloud_sql":                                          _DATABASE_THREATS_V2,
    "gcp_bigquery":                                           _ANALYTICS_DB_THREATS,

    # ── GCP Storage ───────────────────────────────────────────────────────────
    "gcp_cloud_storage":                                      _STORAGE_THREATS,

    # ── GCP Messaging ─────────────────────────────────────────────────────────
    "gcp_pubsub":                                             _MQ_THREATS,

    # ── GCP Networking ────────────────────────────────────────────────────────
    "gcp_cloud_load_balancing":                               _LB_THREATS,
    "gcp_virtual_private_cloud":                              _VPC_THREATS,

    # ── GCP IAM ───────────────────────────────────────────────────────────────
    "gcp_identity_and_access_management":                     _IAM_THREATS,

    # ── GCP ML / AI ───────────────────────────────────────────────────────────
    "gcp_vertex_ai":                                          _MLAI_THREATS,
}

COMPONENT_THREATS.update(_V2_ENTRIES)


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
