# Archive Directory

This directory contains deprecated or incomplete components that were removed from the active project structure but preserved for historical reference.

---

## 📦 Archived Components

### `medusa-backend/` - Archived on October 31, 2025

**Reason for Archival:**  
The Node.js/Express backend was an incomplete implementation that did not align with the MEDUSA CLI's requirements. After a comprehensive audit, it was determined that:

1. **Incomplete API Coverage**: Only implemented basic `/api/patients` and `/api/employees` endpoints
2. **Misaligned Architecture**: Did not provide the pentest-specific endpoints the CLI expected:
   - Missing `/api/reconnaissance`
   - Missing `/api/enumerate`
   - Missing `/api/exploit`
   - Missing `/api/exfiltrate`
   - Missing `/api/report`
3. **Better Alternative Available**: The `lab-environment/` Docker infrastructure provides a more comprehensive and realistic target environment for penetration testing
4. **No Integration**: The CLI never integrated with this backend; it was designed to work directly against Docker services

**Project Completion Status:** ~60% complete  
**Last Modified:** October 2025  
**Dependencies:** Express.js, CORS, Helmet, Morgan

**What Was Implemented:**
- Basic Express.js server on port 3001
- Health check endpoint
- Mock patient and employee data routes
- CORS and security middleware
- Basic logging

**What Was Missing:**
- Authentication/authorization
- Actual database connection (used in-memory data)
- Pentest operation endpoints
- API documentation (Swagger/OpenAPI)
- Test suite
- Rate limiting and input validation

**Decision Rationale:**  
Rather than investing effort to complete an architecture that doesn't align with the project's core vision, we archived this backend in favor of:
1. Direct integration with the Docker lab environment
2. Real target applications in `lab-environment/services/`
3. Focus on AI agent capabilities rather than custom backend infrastructure

---

## 🔄 Migration Path

If you need backend functionality:
- **For mock API testing**: Use the CLI's built-in mock client (`medusa/client.py`)
- **For realistic pentesting**: Deploy the Docker lab environment (`lab-environment/docker-compose.yml`)
- **For custom targets**: Add new services to `lab-environment/services/`

---

## 📚 Historical Reference

This archive preserves the backend code for:
- Learning from architectural decisions
- Understanding project evolution
- Potential future reference if similar functionality is needed

**Note:** This code is not maintained and may have security vulnerabilities. Do not deploy in production.

---

**Archived by:** Project MEDUSA Restructure  
**Date:** October 31, 2025  
**Audit Report:** See `/AUDIT_REPORT.md` and `/REPOSITORY_STRUCTURE_AUDIT.md`

