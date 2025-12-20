# Versioning and Release Policy

This project uses a structured, chat-driven versioning model designed to support rapid iteration, QA validation, and clear release communication.

## Versioning Scheme

Versions follow a semantic-like format:

```
0.X.x
```

Where:
- **X (major)** = Major feature additions or significant behavior changes
- **x (patch)** = Bug fixes, refinements, and non-breaking changes

The classification of changes (major vs patch) is decided at the end of each development cycle.

## Chat-Based Version Flow

- **Each new development chat represents a new version in progress**
- All work done within a chat contributes to a single upcoming version
- Version numbers are finalized only after the work is complete

## Release Rules

- Version number changes occur **only** when merging from the `qa` branch into the `main` branch
- Intermediate commits during development do not bump the version
- QA is the validation gate for all versioned releases

## Changelog Requirements

Every version release must include a detailed changelog with the following sections:

### 1. Overview / Highlights
- High-level summary of what changed
- Focus on user-visible improvements and important fixes

### 2. Enhancements
- New features
- UX improvements
- Performance improvements
- Automation or workflow upgrades

### 3. Bug Fixes
- Fixed defects
- Stability improvements
- Regression fixes

### 4. Notes / Things to Know
- Behavioral changes
- Migration steps (if any)
- Configuration changes
- Known limitations or follow-ups

Changelogs should be written clearly for both technical and non-technical readers.

## AI / Agent Enforcement

Any AI assistant or automated agent working in this repository must:
- Follow this versioning model
- Group changes according to this structure
- Never assume version numbers independently
- Ask for confirmation if a change could be classified as either major or patch

---

**This document is authoritative.**
