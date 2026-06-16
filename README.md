# EntraGuard — Azure Identity Security Posture Management

> Continuously assess, monitor, and harden your Microsoft Entra ID tenant against 115+ security checks with step-by-step remediation.

[![Docker Pulls](https://img.shields.io/docker/pulls/jahmed22/entra-guard-api?label=API+Pulls&logo=docker)](https://hub.docker.com/r/jahmed22/entra-guard-api)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey)](https://hub.docker.com/r/jahmed22/entra-guard-api)

## Quick Start

```bash
# 1. Create docker-compose.yml and .env (see docs)
# 2. Pull and start
docker compose pull
docker compose up -d
# 3. Open http://localhost:3000
```

## Features
- **115 automated checks** across 12 security domains
- Step-by-step remediation with Microsoft documentation links
- NIST CSF, CIS Azure v2, and ISO 27001 compliance mapping
- MSAL 2.0 + Local admin authentication
- Multi-user management (Admin / Viewer roles)
- Multi-arch Docker images (AMD64 + ARM64)
- Entirely self-hosted — your data never leaves your infrastructure

## Documentation
Full documentation: [README on GitHub](https://github.com/jahmed-cloud/entra-guard#readme)

## Docker Hub
```bash
docker pull jahmed22/entra-guard-api:latest
docker pull jahmed22/entra-guard-ui:latest
docker pull jahmed22/entra-guard-worker:latest
docker pull jahmed22/entra-guard-scheduler:latest
```

## Built by
**Junaid Ahmed** — [iam@jahmed.cloud](mailto:iam@jahmed.cloud)

MIT License
