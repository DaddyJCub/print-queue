# Printellect Documentation

Central hub for all Printellect device platform docs.

---

## Getting started

| Doc | Audience | Description |
|-----|----------|-------------|
| [Flashing Guide](printellect-flashing-guide.md) | Manufacturer / Developer | Flash MicroPython and firmware onto a blank Pico 2W |
| [Setup My Printellect Base](setup-my-printellect-base.md) | End user | Wi-Fi setup, claiming, and reset instructions |
| [Firmware Development Workflow](printellect-firmware-dev.md) | Developer | Edit firmware → build release → OTA deploy cycle |

## API reference

| Doc | Audience | Description |
|-----|----------|-------------|
| [Device API](printellect-device-api.md) | Firmware / Device | Pico-to-server contract: provision, heartbeat, commands, OTA |
| [User API](printellect-user-api.md) | Frontend / App | Pairing, device control, actions |
| [Admin API](printellect-admin-api.md) | Admin / Ops | Device registry, firmware releases, OTA push |

Auto-generated docs (when server is running):
- **Swagger UI**: `GET /docs`
- **OpenAPI JSON**: `GET /openapi.json`

## Architecture & internals

| Doc | Description |
|-----|-------------|
| [Device State Machine](printellect-device-state-machine.md) | Boot → Wi-Fi → Provision → Run flow diagram |
| [OTA & Recovery](printellect-ota-and-recovery.md) | OTA update model, safety, and wired recovery |
| [Pico API Programming Guide](printellect-pico-api-programming-guide.md) | Complete firmware implementation spec (14 sections) |
| [Pico Integration Handoff](printellect-pico-integration-handoff.md) | Firmware engineer handoff contract |
| [Pico Final Implementation Guide](printellect-pico-final-implementation-guide.md) | v0.17.0+ rollout notes and manufacturing contract |

## Local development

| Doc | Description |
|-----|-------------|
| [Local QA](printellect-local-qa.md) | Running the backend locally for testing |
| [Local Development](dev/local-development.md) | General backend dev setup |
