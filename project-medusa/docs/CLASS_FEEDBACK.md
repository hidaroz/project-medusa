# Class Feedback Summary

## Overview
Class discussion shifted our project from a compelling demo to a measurement-driven study of adaptation, with peers pressing us on decision quality and appropriate action selection beyond toy paths.

## Key Feedback Areas

### 1. Decision Quality & Measurement
- **Phase Scoring**: Our recon → lateral → exfil/encrypt simulation phases with ATT&CK-linked rationales helped make choices legible
- **Challenge**: Justifications thin out under time pressure
- **Action**: Need to strengthen decision-making frameworks under stress

### 2. Legal/Ethical Exposure
- **Issue**: Physical-USB narrative created ambiguity
- **Resolution**: Committed to sandbox-only, camera-free, synthetic hardware vectors
- **Action**: Document IRB-style guardrails for ethical compliance

### 3. RAG/Data Plumbing
- **Feedback**: "Adding files" isn't rigor
- **Improvements**:
  - Curated, versioned corpora with freshness targets
  - Rollback procedures
  - With/without-RAG ablations for auditable benefits/harm claims

### 4. Generalization & Human-in-the-Loop (HIL)
- **Requirement**: Be explicit about when humans arbitrate and consistency
- **Implementation**:
  - Risk-tier matrix
  - Early reporting on override rate and inter-rater reliability
  - Surface where operator guidance diverges and prompts need tightening

### 5. Residuals/Forensics
- **Concerns**: Artifact detection and forensic analysis
- **Quantification Needed**:
  - Artifact counts
  - Alert footprints
  - Dwell time on hardened images
- **Enhancement**: Self-debrief loop after detections

### 6. Authentication/RBAC Security
- **Issues**: JWT replay/expiry/forgery concerns
- **Testing**: Token fuzzing and cross-role checks
- **Status**: Initial blocks behave as expected
- **Requirement**: Systematic reporting as release criterion

### 7. Output Reviewability
- **Problem**: Raw TXT output hard to review
- **Solution**: 
  - Structured tables/cards
  - Persona-specific panels
  - Always-visible ATT&CK traceability
- **Result**: Improved reviewability without changing underlying results

## Summary
The class feedback transformed our approach from a demo-focused project to a rigorous, measurement-driven study with clear ethical boundaries, systematic data handling, and improved human-AI interaction frameworks. Key improvements include better decision documentation, enhanced security testing, and more reviewable output formats.
