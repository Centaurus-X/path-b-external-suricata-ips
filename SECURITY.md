# Security Policy

Path-B v5.12 is a non-production lab preview. It is not approved for production traffic.

## Sensitive files

Do not commit or publish:

- generated CA private keys,
- generated Squid CA material,
- Windows client kits containing a generated CA,
- production logs,
- personal data,
- customer data,
- packet captures from real networks,
- credentials or API tokens.

## Lab exposure

Restrict access to:

```text
Squid TCP/3128      test clients only
Squid TCP/3129      local interception tests only
ICAP TCP/1345       proxy VM only
Health TCP/2345     management/test network only
```

## Responsible reporting

Do not post sensitive data in public issues. For public releases, provide a private contact channel in the repository profile or organization profile.

## Legal and compliance reminder

TLS inspection may be subject to law, regulation, privacy requirements, employment agreements, customer contracts, and organizational policy. Obtain all required approvals before testing or deploying.
