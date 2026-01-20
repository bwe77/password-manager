### About
create a Password Breach Monitoring & Credential Manager
Build a security-focused password manager with breach detection and password health monitoring.
Tech Stack:
* Backend: Spring Boot (Java) with strong encryption (AES-256)
* Frontend: angular with security-focused UI/UX
* Database: PostgreSQL with encrypted fields
* Cache: Redis for session management and rate limiting
* API Integration: Have I Been Pwned API
* DevOps: Docker with security hardening
Key Features:
* Encrypted password storage with master password (zero-knowledge architecture)
* Password strength analyzer with entropy calculation
* Breach detection using Have I Been Pwned API (k-anonymity model)
* Password generation with customizable rules
* Two-factor authentication (TOTP)
* Audit log of all password access attempts
* Security dashboard showing weak/reused/breached passwords
* Automatic password expiration reminders
* Secure password sharing with time-limited access
What Makes It Intermediate:
* Implementing proper encryption at rest and in transit
* Zero-knowledge architecture design
* Secure key derivation (PBKDF2/Argon2)
* Implementing k-anonymity for API queries (privacy-preserving breach checks)
* Secure session management and authentication flows
* Protecting against timing attacks and side-channel attacks. show me how to start from the backend as in wut controllers, services, etc do i need . do not give the full code but maybe just outline the files needed and a start to each of the components as guidance

### Memory Management
- Memory leaks or retained references
- Loading entire datasets when streaming is possible
- Excessive object instantiation in loops
- Large data structures kept in memory unnecessarily
- Missing garbage collection opportunities

### Useless files
Remove or suggest removal of files which have no use in the present

