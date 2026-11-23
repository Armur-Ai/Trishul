# Rule catalog

162 rules. Generated from the rule catalog by `trishul-rulesdoc`; do not edit by hand.

| ID | Title | Severity | Maturity |
| --- | --- | --- | --- |
| [AGENT-CHAIN-001](AGENT-CHAIN-001.md) | Cross-file agent attack chain: untrusted content + an enabled execution/permission path | CRITICAL | stable |
| [AGENT-EXEC-001](AGENT-EXEC-001.md) | Risky install-lifecycle script in package.json | HIGH | stable |
| [AGENT-EXEC-002](AGENT-EXEC-002.md) | Risky install/build script execution path | HIGH | stable |
| [AGENT-EXEC-003](AGENT-EXEC-003.md) | Risky CI workflow execution path | HIGH | stable |
| [AGENT-INJ-001](AGENT-INJ-001.md) | Prompt-injection directive in source-code comment | MEDIUM | beta |
| [AGENT-INJ-002](AGENT-INJ-002.md) | Prompt-injection directive in documentation or fixture | MEDIUM | beta |
| [AGENT-INJ-003](AGENT-INJ-003.md) | Prompt-injection directive in issue/PR template | MEDIUM | beta |
| [AGENT-INSTR-001](AGENT-INSTR-001.md) | Instruction-override attempt in agent instruction file | MEDIUM | stable |
| [AGENT-INSTR-002](AGENT-INSTR-002.md) | System/developer authority impersonation in instruction file | MEDIUM | stable |
| [AGENT-INSTR-003](AGENT-INSTR-003.md) | Agent role or authority escalation directive | MEDIUM | stable |
| [AGENT-INSTR-004](AGENT-INSTR-004.md) | Sensitive-action directive in agent instruction file | HIGH | stable |
| [AGENT-MCP-001](AGENT-MCP-001.md) | MCP server launched via unpinned package runner | HIGH | stable |
| [AGENT-MCP-002](AGENT-MCP-002.md) | MCP server fetches and runs remote code | HIGH | stable |
| [AGENT-MCP-003](AGENT-MCP-003.md) | Secret embedded in MCP server config | HIGH | stable |
| [AGENT-MCP-004](AGENT-MCP-004.md) | Remote MCP server configured — review its trust | MEDIUM | beta |
| [AGENT-OBFS-001](AGENT-OBFS-001.md) | Hidden or bidirectional Unicode concealing text | MEDIUM | stable |
| [AGENT-OBFS-002](AGENT-OBFS-002.md) | Homoglyph/confusable disguising a security keyword | MEDIUM | stable |
| [AGENT-OBFS-003](AGENT-OBFS-003.md) | Encoded blob decodes to instruction-like text | HIGH | stable |
| [AGENT-OBFS-004](AGENT-OBFS-004.md) | Directive hidden in a comment invisible when rendered | HIGH | stable |
| [AGENT-PERM-001](AGENT-PERM-001.md) | Blanket allow-all tool permissions | HIGH | stable |
| [AGENT-PERM-002](AGENT-PERM-002.md) | Agent approval/confirmation disabled | HIGH | stable |
| [AGENT-PERM-003](AGENT-PERM-003.md) | Dangerous permission/sandbox-bypass flag | HIGH | stable |
| [AGENT-PERM-004](AGENT-PERM-004.md) | Security check disabled | MEDIUM | stable |
| [CLIENT-SECRET-001](CLIENT-SECRET-001.md) | Secret assigned to a client-exposed environment variable | HIGH | stable |
| [CLIENT-SECRET-002](CLIENT-SECRET-002.md) | Committed .env file contains a secret | HIGH | stable |
| [CLIENT-SECRET-003](CLIENT-SECRET-003.md) | Privileged secret in a client-side file | CRITICAL | stable |
| [EXPLOIT-ASPNET-CUSTOMERRORS-OFF-001](EXPLOIT-ASPNET-CUSTOMERRORS-OFF-001.md) | ASP.NET custom errors disabled (<customErrors mode="Off">) | MEDIUM | stable |
| [EXPLOIT-ASPNET-DEBUG-001](EXPLOIT-ASPNET-DEBUG-001.md) | ASP.NET compilation debug enabled (<compilation debug="true">) | MEDIUM | stable |
| [EXPLOIT-ASPNET-MACHINEKEY-001](EXPLOIT-ASPNET-MACHINEKEY-001.md) | ASP.NET hardcoded machineKey validationKey | HIGH | stable |
| [EXPLOIT-ASPNET-TRACE-001](EXPLOIT-ASPNET-TRACE-001.md) | ASP.NET tracing enabled (<trace enabled="true">) | MEDIUM | stable |
| [EXPLOIT-AZURE-BLOB-PUBLIC-001](EXPLOIT-AZURE-BLOB-PUBLIC-001.md) | Azure blob container allows anonymous public access | HIGH | stable |
| [EXPLOIT-AZURE-NSG-OPEN-001](EXPLOIT-AZURE-NSG-OPEN-001.md) | Azure NSG rule allows a sensitive port inbound from any source | HIGH | stable |
| [EXPLOIT-AZURE-STORAGE-PUBLIC-001](EXPLOIT-AZURE-STORAGE-PUBLIC-001.md) | Azure storage account permits anonymous public blob access | HIGH | stable |
| [EXPLOIT-AZURE-STORAGE-WEAKTLS-001](EXPLOIT-AZURE-STORAGE-WEAKTLS-001.md) | Azure storage account accepts legacy TLS (min_tls_version < 1.2) | MEDIUM | stable |
| [EXPLOIT-COMPOSE-HOST-ACCESS-001](EXPLOIT-COMPOSE-HOST-ACCESS-001.md) | Docker Compose service breaks host isolation | HIGH | stable |
| [EXPLOIT-COOKIE-HTTPONLY-001](EXPLOIT-COOKIE-HTTPONLY-001.md) | Session cookie HttpOnly disabled (readable by XSS) | MEDIUM | stable |
| [EXPLOIT-COOKIE-SECURE-001](EXPLOIT-COOKIE-SECURE-001.md) | Session/CSRF cookie Secure flag disabled (sent over plain HTTP) | MEDIUM | stable |
| [EXPLOIT-CORRELATED-001](EXPLOIT-CORRELATED-001.md) | Correlated exploit chain across multiple findings | CRITICAL | stable |
| [EXPLOIT-CORS-CREDS-001](EXPLOIT-CORS-CREDS-001.md) | Exploitable CORS: credentials allowed with a wildcard/reflected origin | HIGH | stable |
| [EXPLOIT-CSRF-DISABLED-001](EXPLOIT-CSRF-DISABLED-001.md) | CSRF protection disabled | MEDIUM | stable |
| [EXPLOIT-DJANGO-DEBUG-001](EXPLOIT-DJANGO-DEBUG-001.md) | Django DEBUG=True in settings (traceback + settings/secret leak on every error) | HIGH | stable |
| [EXPLOIT-DJANGO-HOSTS-001](EXPLOIT-DJANGO-HOSTS-001.md) | Django ALLOWED_HOSTS set to '*' (host-header attacks) | MEDIUM | stable |
| [EXPLOIT-DJANGO-INSECURE-TRANSPORT-001](EXPLOIT-DJANGO-INSECURE-TRANSPORT-001.md) | Django production settings disable HTTPS enforcement (SSL redirect / HSTS off) | MEDIUM | stable |
| [EXPLOIT-DOCKER-ADD-REMOTE-001](EXPLOIT-DOCKER-ADD-REMOTE-001.md) | Dockerfile ADD fetches a remote URL into the image | MEDIUM | stable |
| [EXPLOIT-DOCKER-CURL-PIPE-001](EXPLOIT-DOCKER-CURL-PIPE-001.md) | Dockerfile pipes a remote script into a shell (curl \| sh) | HIGH | stable |
| [EXPLOIT-DOTNET-FORMATTER-001](EXPLOIT-DOTNET-FORMATTER-001.md) | .NET insecure formatter (BinaryFormatter/LosFormatter/...) -> RCE | HIGH | stable |
| [EXPLOIT-DOTNET-JSONNET-001](EXPLOIT-DOTNET-JSONNET-001.md) | Json.NET TypeNameHandling allows gadget deserialization -> RCE | HIGH | stable |
| [EXPLOIT-DRUPAL-SETTINGS-001](EXPLOIT-DRUPAL-SETTINGS-001.md) | Drupal settings.php has a dangerous production setting | MEDIUM | stable |
| [EXPLOIT-EMAIL-HEADER-INJECT-001](EXPLOIT-EMAIL-HEADER-INJECT-001.md) | Email header injection — request input concatenated into an email header | HIGH | stable |
| [EXPLOIT-FASTJSON-AUTOTYPE-001](EXPLOIT-FASTJSON-AUTOTYPE-001.md) | Fastjson autoType enabled — deserialization RCE precondition | CRITICAL | stable |
| [EXPLOIT-FILE-UPLOAD-001](EXPLOIT-FILE-UPLOAD-001.md) | Insecure file upload — saved under an unvalidated user-controlled filename | HIGH | stable |
| [EXPLOIT-FLASK-DEBUG-001](EXPLOIT-FLASK-DEBUG-001.md) | Flask/Werkzeug debug mode enabled (interactive-debugger RCE surface) | HIGH | stable |
| [EXPLOIT-GCP-FIREWALL-OPEN-001](EXPLOIT-GCP-FIREWALL-OPEN-001.md) | GCP firewall opens a sensitive port to the internet (0.0.0.0/0) | HIGH | stable |
| [EXPLOIT-GCP-GCS-PUBLIC-001](EXPLOIT-GCP-GCS-PUBLIC-001.md) | GCS bucket IAM grants access to allUsers/allAuthenticatedUsers (public) | HIGH | stable |
| [EXPLOIT-GO-XSS-001](EXPLOIT-GO-XSS-001.md) | html/template auto-escaping bypassed (template.HTML/JS/URL on a variable) -> XSS | HIGH | stable |
| [EXPLOIT-GRAPHQL-INTROSPECT-001](EXPLOIT-GRAPHQL-INTROSPECT-001.md) | GraphQL introspection enabled (full schema disclosure) | MEDIUM | stable |
| [EXPLOIT-GRPC-REFLECTION-001](EXPLOIT-GRPC-REFLECTION-001.md) | gRPC server reflection registered (API surface disclosure) | LOW | stable |
| [EXPLOIT-HARDCODED-KEY-001](EXPLOIT-HARDCODED-KEY-001.md) | Hardcoded cryptographic key/IV in a cipher constructor | HIGH | stable |
| [EXPLOIT-HTTP-HEADER-INJECT-001](EXPLOIT-HTTP-HEADER-INJECT-001.md) | HTTP response header injection — request input written into a response header | MEDIUM | stable |
| [EXPLOIT-JAVA-JACKSON-001](EXPLOIT-JAVA-JACKSON-001.md) | Jackson default typing enabled -> polymorphic gadget deserialization RCE | HIGH | stable |
| [EXPLOIT-JAVA-OIS-001](EXPLOIT-JAVA-OIS-001.md) | Java ObjectInputStream.readObject deserialization surface | MEDIUM | stable |
| [EXPLOIT-JAVA-SNAKEYAML-001](EXPLOIT-JAVA-SNAKEYAML-001.md) | Unsafe SnakeYAML load (arbitrary type construction -> RCE) | HIGH | stable |
| [EXPLOIT-JAVA-XMLDECODER-001](EXPLOIT-JAVA-XMLDECODER-001.md) | java.beans.XMLDecoder on untrusted input -> RCE | HIGH | stable |
| [EXPLOIT-JWT-NONE-001](EXPLOIT-JWT-NONE-001.md) | JWT 'none' algorithm accepted (unsigned tokens → identity forgery) | CRITICAL | stable |
| [EXPLOIT-JWT-NOVERIFY-001](EXPLOIT-JWT-NOVERIFY-001.md) | JWT signature verification disabled (identity forgery) | HIGH | stable |
| [EXPLOIT-K8S-HOST-NAMESPACE-001](EXPLOIT-K8S-HOST-NAMESPACE-001.md) | Kubernetes pod joins a host namespace / mounts a host path | HIGH | stable |
| [EXPLOIT-K8S-HOSTPORT-001](EXPLOIT-K8S-HOSTPORT-001.md) | Kubernetes container binds a hostPort (node-level network exposure) | MEDIUM | stable |
| [EXPLOIT-K8S-PRIV-ESCALATION-001](EXPLOIT-K8S-PRIV-ESCALATION-001.md) | Kubernetes container allows privilege escalation | HIGH | stable |
| [EXPLOIT-K8S-PRIVILEGED-001](EXPLOIT-K8S-PRIVILEGED-001.md) | Kubernetes privileged container | HIGH | stable |
| [EXPLOIT-K8S-RBAC-WILDCARD-001](EXPLOIT-K8S-RBAC-WILDCARD-001.md) | Kubernetes RBAC rule grants all verbs on all resources (cluster-admin-equivalent) | HIGH | stable |
| [EXPLOIT-LARAVEL-DEBUG-001](EXPLOIT-LARAVEL-DEBUG-001.md) | Laravel debug mode enabled in a live .env (Ignition RCE + info leak surface) | HIGH | stable |
| [EXPLOIT-LDAP-INJECT-001](EXPLOIT-LDAP-INJECT-001.md) | LDAP injection — request input concatenated into a search filter | HIGH | stable |
| [EXPLOIT-LOG4SHELL-REACH-001](EXPLOIT-LOG4SHELL-REACH-001.md) | Log4Shell reachability — request-controlled input logged (RCE if log4j is vulnerable) | HIGH | stable |
| [EXPLOIT-MASS-ASSIGN-001](EXPLOIT-MASS-ASSIGN-001.md) | Mass assignment — whole request body bound without an allowlist | HIGH | stable |
| [EXPLOIT-NEXTJS-29927-001](EXPLOIT-NEXTJS-29927-001.md) | Next.js middleware auth bypass (x-middleware-subrequest) | HIGH | stable |
| [EXPLOIT-NODE-CMDI-001](EXPLOIT-NODE-CMDI-001.md) | OS command injection — request input reaches child_process | CRITICAL | stable |
| [EXPLOIT-NODE-CODEI-001](EXPLOIT-NODE-CODEI-001.md) | Code injection — request input reaches eval() | CRITICAL | stable |
| [EXPLOIT-NODE-CODEI-002](EXPLOIT-NODE-CODEI-002.md) | Code injection — request input reaches new Function() | CRITICAL | stable |
| [EXPLOIT-NODE-CODEI-003](EXPLOIT-NODE-CODEI-003.md) | Code injection — request input reaches vm.run* | HIGH | stable |
| [EXPLOIT-NOSQL-001](EXPLOIT-NOSQL-001.md) | NoSQL injection — request object passed to a query | HIGH | stable |
| [EXPLOIT-OPEN-REDIRECT-001](EXPLOIT-OPEN-REDIRECT-001.md) | Open redirect — redirect destination is request-controlled | MEDIUM | stable |
| [EXPLOIT-PATH-TRAVERSAL-001](EXPLOIT-PATH-TRAVERSAL-001.md) | Path traversal — filesystem path built from request input | HIGH | stable |
| [EXPLOIT-PHP-CMDI-001](EXPLOIT-PHP-CMDI-001.md) | OS command injection — request input reaches a shell sink | CRITICAL | stable |
| [EXPLOIT-PHP-CODEI-001](EXPLOIT-PHP-CODEI-001.md) | PHP code injection — request input reaches eval() | CRITICAL | stable |
| [EXPLOIT-PHP-DESER-001](EXPLOIT-PHP-DESER-001.md) | PHP object injection — unserialize() on request input | HIGH | stable |
| [EXPLOIT-PHP-LFI-001](EXPLOIT-PHP-LFI-001.md) | File inclusion (LFI/RFI) — request input in an include path | HIGH | stable |
| [EXPLOIT-PROTO-POLLUTION-001](EXPLOIT-PROTO-POLLUTION-001.md) | Prototype pollution — request input reaches a recursive merge / path-set | HIGH | stable |
| [EXPLOIT-PY-CMDI-001](EXPLOIT-PY-CMDI-001.md) | OS command injection — request input reaches os.system() | CRITICAL | stable |
| [EXPLOIT-PY-CMDI-002](EXPLOIT-PY-CMDI-002.md) | OS command injection — request input in subprocess(shell=True) | CRITICAL | stable |
| [EXPLOIT-PY-CODEI-001](EXPLOIT-PY-CODEI-001.md) | Python code injection — request input reaches eval()/exec() | CRITICAL | stable |
| [EXPLOIT-PY-DESER-001](EXPLOIT-PY-DESER-001.md) | Insecure deserialization — pickle on request input | HIGH | stable |
| [EXPLOIT-PY-YAML-LOAD-001](EXPLOIT-PY-YAML-LOAD-001.md) | Unsafe YAML deserialization (yaml.load without SafeLoader → RCE on untrusted input) | HIGH | stable |
| [EXPLOIT-RAILS-DEBUG-001](EXPLOIT-RAILS-DEBUG-001.md) | Rails consider_all_requests_local=true in production (error pages + stack traces leak) | HIGH | stable |
| [EXPLOIT-RAILS-FORCE-SSL-001](EXPLOIT-RAILS-FORCE-SSL-001.md) | Rails production disables forced HTTPS (config.force_ssl = false) | MEDIUM | stable |
| [EXPLOIT-RAILS-SECRET-001](EXPLOIT-RAILS-SECRET-001.md) | Hardcoded Rails secret_key_base (session/cookie forgery) | HIGH | stable |
| [EXPLOIT-REACT-XSS-001](EXPLOIT-REACT-XSS-001.md) | dangerouslySetInnerHTML with an unsanitized value -> XSS | MEDIUM | stable |
| [EXPLOIT-REFLECTED-XSS-001](EXPLOIT-REFLECTED-XSS-001.md) | Reflected XSS — request input written into the response | MEDIUM | stable |
| [EXPLOIT-RUBY-CMDI-001](EXPLOIT-RUBY-CMDI-001.md) | OS command injection — request input reaches system()/exec() | CRITICAL | stable |
| [EXPLOIT-RUBY-CMDI-002](EXPLOIT-RUBY-CMDI-002.md) | OS command injection — request input reaches IO.popen/Open3 | CRITICAL | stable |
| [EXPLOIT-RUBY-CMDI-003](EXPLOIT-RUBY-CMDI-003.md) | OS command injection — request input in a backtick/%x shell command | CRITICAL | stable |
| [EXPLOIT-RUBY-CODEI-001](EXPLOIT-RUBY-CODEI-001.md) | Ruby code injection — request input reaches eval() | CRITICAL | stable |
| [EXPLOIT-RUBY-OPEN-001](EXPLOIT-RUBY-OPEN-001.md) | Request input reaches Kernel#open (command/file injection) | HIGH | stable |
| [EXPLOIT-SIGNING-KEY-001](EXPLOIT-SIGNING-KEY-001.md) | Hardcoded SECRET_KEY (session/cookie forgery -> auth bypass) | HIGH | stable |
| [EXPLOIT-SPRING-ACTUATOR-001](EXPLOIT-SPRING-ACTUATOR-001.md) | Spring Actuator exposes sensitive endpoints over the web | HIGH | stable |
| [EXPLOIT-SPRING-ACTUATOR-002](EXPLOIT-SPRING-ACTUATOR-002.md) | Spring Actuator /shutdown endpoint enabled | HIGH | stable |
| [EXPLOIT-SPRING-H2-CONSOLE-001](EXPLOIT-SPRING-H2-CONSOLE-001.md) | Spring Boot H2 web console enabled | HIGH | stable |
| [EXPLOIT-SPRING-SPEL-001](EXPLOIT-SPRING-SPEL-001.md) | SpEL injection — request input parsed as a Spring Expression | CRITICAL | stable |
| [EXPLOIT-SPRING-STACKTRACE-001](EXPLOIT-SPRING-STACKTRACE-001.md) | Spring Boot returns full stack traces in responses (include-stacktrace=always) | MEDIUM | stable |
| [EXPLOIT-SQLI-001](EXPLOIT-SQLI-001.md) | SQL injection — request input concatenated into a SQL query | CRITICAL | stable |
| [EXPLOIT-SSRF-001](EXPLOIT-SSRF-001.md) | Server-side request forgery — request-controlled URL fetched | HIGH | stable |
| [EXPLOIT-SSTI-001](EXPLOIT-SSTI-001.md) | Server-side template injection — request input rendered as a template | CRITICAL | stable |
| [EXPLOIT-SSTI-ENGINE-001](EXPLOIT-SSTI-ENGINE-001.md) | Server-side template injection — request input compiled as a template | CRITICAL | stable |
| [EXPLOIT-TEXT4SHELL-001](EXPLOIT-TEXT4SHELL-001.md) | Text4Shell — request input passed to commons-text interpolator | CRITICAL | stable |
| [EXPLOIT-TF-CLOUDTRAIL-DISABLED-001](EXPLOIT-TF-CLOUDTRAIL-DISABLED-001.md) | AWS CloudTrail logging disabled (enable_logging = false) | MEDIUM | stable |
| [EXPLOIT-TF-CLOUDTRAIL-SINGLE-REGION-001](EXPLOIT-TF-CLOUDTRAIL-SINGLE-REGION-001.md) | AWS CloudTrail is not multi-region (is_multi_region_trail = false) | LOW | stable |
| [EXPLOIT-TF-EKS-PUBLIC-001](EXPLOIT-TF-EKS-PUBLIC-001.md) | EKS Kubernetes API server is reachable from the internet (public_access_cidrs 0.0.0.0/0) | HIGH | stable |
| [EXPLOIT-TF-IAM-WILDCARD-001](EXPLOIT-TF-IAM-WILDCARD-001.md) | Terraform IAM policy grants Action "*" on Resource "*" (admin-equivalent) | HIGH | stable |
| [EXPLOIT-TF-IMDSV1-001](EXPLOIT-TF-IMDSV1-001.md) | AWS instance allows IMDSv1 (http_tokens = optional) — SSRF-to-credential-theft precondition | HIGH | stable |
| [EXPLOIT-TF-LAMBDA-PUBLIC-001](EXPLOIT-TF-LAMBDA-PUBLIC-001.md) | AWS Lambda permission grants invoke to any principal (principal = "*") | HIGH | stable |
| [EXPLOIT-TF-OPEN-INGRESS-001](EXPLOIT-TF-OPEN-INGRESS-001.md) | Terraform security group opens a sensitive port to the internet (0.0.0.0/0) | HIGH | stable |
| [EXPLOIT-TF-PUBLIC-AMI-001](EXPLOIT-TF-PUBLIC-AMI-001.md) | AWS AMI/snapshot shared publicly (launch permission group = "all") | HIGH | stable |
| [EXPLOIT-TF-PUBLIC-RESOURCE-POLICY-001](EXPLOIT-TF-PUBLIC-RESOURCE-POLICY-001.md) | Terraform resource policy allows a wildcard principal (public access) | HIGH | stable |
| [EXPLOIT-TF-RDS-PUBLIC-001](EXPLOIT-TF-RDS-PUBLIC-001.md) | Terraform database is publicly accessible | HIGH | stable |
| [EXPLOIT-TF-RDS-UNENCRYPTED-001](EXPLOIT-TF-RDS-UNENCRYPTED-001.md) | Terraform database storage is unencrypted | MEDIUM | stable |
| [EXPLOIT-TF-S3-PUBLIC-001](EXPLOIT-TF-S3-PUBLIC-001.md) | Terraform exposes object storage publicly | HIGH | stable |
| [EXPLOIT-TF-UNENCRYPTED-VOLUME-001](EXPLOIT-TF-UNENCRYPTED-VOLUME-001.md) | Terraform block storage is unencrypted at rest (encrypted = false) | MEDIUM | stable |
| [EXPLOIT-TLS-NOVERIFY-001](EXPLOIT-TLS-NOVERIFY-001.md) | TLS certificate verification disabled | HIGH | stable |
| [EXPLOIT-VERBOSE-ERROR-001](EXPLOIT-VERBOSE-ERROR-001.md) | Verbose error exposure — stack trace / traceback returned to the client | MEDIUM | stable |
| [EXPLOIT-WEAK-PWHASH-001](EXPLOIT-WEAK-PWHASH-001.md) | Weak password hashing — a fast digest (MD5/SHA-1/SHA-256) is used for a credential | HIGH | stable |
| [EXPLOIT-WEAK-RANDOM-001](EXPLOIT-WEAK-RANDOM-001.md) | Insecure randomness for a security value (predictable token/secret) | MEDIUM | stable |
| [EXPLOIT-WORDPRESS-DEBUG-001](EXPLOIT-WORDPRESS-DEBUG-001.md) | WordPress debug mode enabled in wp-config.php | MEDIUM | stable |
| [EXPLOIT-XPATH-INJECT-001](EXPLOIT-XPATH-INJECT-001.md) | XPath injection — request input concatenated into an XPath expression | HIGH | stable |
| [EXPLOIT-XXE-001](EXPLOIT-XXE-001.md) | XML external entities enabled | HIGH | stable |
| [EXPLOIT-ZIP-SLIP-001](EXPLOIT-ZIP-SLIP-001.md) | Zip-Slip — extraction path built from an unvalidated archive entry name | HIGH | stable |
| [FIREBASE-001](FIREBASE-001.md) | Firestore rule allows world read and write | CRITICAL | stable |
| [FIREBASE-002](FIREBASE-002.md) | Firestore/Storage rule allows any authenticated user without ownership check | HIGH | stable |
| [FIREBASE-003](FIREBASE-003.md) | Cloud Storage rule grants an unconditional allow | HIGH | stable |
| [FIREBASE-004](FIREBASE-004.md) | Broad {document=**} catch-all with a permissive allow | MEDIUM | stable |
| [SUPABASE-RLS-001](SUPABASE-RLS-001.md) | Table created without row-level security | HIGH | stable |
| [SUPABASE-RLS-002](SUPABASE-RLS-002.md) | RLS policy with an always-true predicate (effectively public) | CRITICAL | stable |
| [SUPABASE-RLS-003](SUPABASE-RLS-003.md) | RLS policy grants write/ALL to the anon role | HIGH | stable |
| [SUPABASE-RLS-004](SUPABASE-RLS-004.md) | SECURITY DEFINER function without a pinned search_path | HIGH | stable |
| [SUPABASE-RLS-005](SUPABASE-RLS-005.md) | Public storage bucket | HIGH | stable |
| [VIBE-ABUSE-001](VIBE-ABUSE-001.md) | Auth or LLM endpoint without rate limiting | MEDIUM | stable |
| [VIBE-ABUSE-002](VIBE-ABUSE-002.md) | File upload handler without a size limit | MEDIUM | stable |
| [VIBE-ABUSE-003](VIBE-ABUSE-003.md) | Unvalidated req.body spread into a database write | LOW | stable |
| [VIBE-AUTHZ-001](VIBE-AUTHZ-001.md) | Unauthenticated data route (missing authorization) | HIGH | stable |
| [VIBE-AUTHZ-002](VIBE-AUTHZ-002.md) | IDOR: record looked up by request id without owner scoping | HIGH | stable |
| [VIBE-DEP-001](VIBE-DEP-001.md) | Dependency sourced from a non-registry location | MEDIUM | stable |
| [VIBE-DEP-002](VIBE-DEP-002.md) | Unpinned dependency with no lockfile | LOW | stable |
| [VIBE-DEP-003](VIBE-DEP-003.md) | Overrides/resolutions repoint a package to a non-registry source | MEDIUM | stable |
| [VIBE-LLM-001](VIBE-LLM-001.md) | Untrusted input interpolated into an LLM prompt (prompt injection) | HIGH | stable |
| [VIBE-LLM-002](VIBE-LLM-002.md) | LLM output flows into a dangerous sink | HIGH | stable |
| [VIBE-LLM-003](VIBE-LLM-003.md) | Provider API key used in client-side code | CRITICAL | stable |
| [VIBE-PLACEHOLDER-001](VIBE-PLACEHOLDER-001.md) | Hardcoded placeholder or weak signing secret | HIGH | stable |
| [VIBE-PLACEHOLDER-002](VIBE-PLACEHOLDER-002.md) | Default or well-known credentials | HIGH | stable |
| [VIBE-PLACEHOLDER-003](VIBE-PLACEHOLDER-003.md) | Disabled TLS/certificate verification | HIGH | stable |
| [VIBE-PLACEHOLDER-004](VIBE-PLACEHOLDER-004.md) | Wildcard CORS origin combined with credentials | HIGH | stable |
| [VIBE-PLACEHOLDER-005](VIBE-PLACEHOLDER-005.md) | Debug mode enabled | MEDIUM | stable |
| [VIBE-PLACEHOLDER-006](VIBE-PLACEHOLDER-006.md) | Security-related TODO/FIXME marker | LOW | stable |
| [VIBE-WEBHOOK-001](VIBE-WEBHOOK-001.md) | Unverified provider webhook handler | HIGH | stable |
| [VIBE-WEBHOOK-002](VIBE-WEBHOOK-002.md) | Client-trusted payment/access value from request body | HIGH | stable |
