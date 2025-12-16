# Multi-Build System Test Plan

## Prerequisites
- Application running locally with test data
- At least one printer configured and accessible
- Email/push notification settings configured (optional for notification tests)

---

## 1. Single-Build Request (Backward Compatibility)

| Step | Action | Expected |
|------|--------|----------|
| 1.1 | Create request with 1 file | `total_builds=1`, no builds table entries initially |
| 1.2 | Admin approves → assigns printer | Request status = `APPROVED` |
| 1.3 | Admin starts print (legacy flow) | Status = `PRINTING`, `printing_started_at` set |
| 1.4 | View `/my/{rid}` page | Shows standard progress, NO "Build X of Y" indicator |
| 1.5 | Printer completes | Status = `DONE`, notification sent |
| 1.6 | Check ETA display | Shows single ETA (not "This Build Done" / "All Builds Done") |

---

## 2. Multi-Build Request Creation

| Step | Action | Expected |
|------|--------|----------|
| 2.1 | Create request with multiple files | `total_builds` matches file count |
| 2.2 | Admin calls `setup_builds_for_request(rid)` | Builds created in `builds` table |
| 2.3 | Verify builds | Each build has: `build_number`, `status=PENDING`, `request_id` |
| 2.4 | Admin calls `mark_builds_ready(rid)` | All builds → `status=READY` |

---

## 3. Multi-Build Printing Flow

| Step | Action | Expected |
|------|--------|----------|
| 3.1 | Admin calls `start_build(build_id, printer)` | Build → `PRINTING`, request → `IN_PROGRESS` |
| 3.2 | View `/my/{rid}` | Shows "Build 1 of N", progress dots, "This Build Done" ETA |
| 3.3 | Build completes (via polling or manual) | Build → `COMPLETED`, snapshot captured |
| 3.4 | Request status | Still `IN_PROGRESS` (not all builds done) |
| 3.5 | Start next build | New build → `PRINTING`, previous stays `COMPLETED` |
| 3.6 | Final build completes | Request → `DONE`, final notification sent |

---

## 4. Partial Completion States

| Step | Action | Expected |
|------|--------|----------|
| 4.1 | Complete builds 1, 2 of 3 | `completed_builds=2`, request = `IN_PROGRESS` |
| 4.2 | Check `/my/{rid}` UI | Shows 2 green dots, 1 gray dot |
| 4.3 | Leave build 3 as `READY` (not started) | Request stays `IN_PROGRESS` |
| 4.4 | Verify `derive_request_status_from_builds()` | Returns `IN_PROGRESS` (has pending builds) |

---

## 5. Build Failures

| Step | Action | Expected |
|------|--------|----------|
| 5.1 | Start build 1, call `fail_build(build_id)` | Build → `FAILED`, request → `BLOCKED` |
| 5.2 | View `/my/{rid}` | Shows red dot for failed build, warning message |
| 5.3 | Call `retry_build(build_id)` | Build → `PENDING`, request stays `BLOCKED` |
| 5.4 | Re-start build | Build → `PRINTING`, request → `IN_PROGRESS` |
| 5.5 | Skip failed build: `skip_build(build_id)` | Build → `SKIPPED`, request recalculates |

---

## 6. Notifications

### 6.1 Build Start Notifications (Multi-Build Only)
| Condition | Expected |
|-----------|----------|
| Single-build request starts | NO build notification (legacy handles it) |
| Multi-build build 1 starts | Email: "Build 1 of 3 Started", amber header |
| Multi-build build 2 starts | Email: "Build 2 of 3 Started" |

### 6.2 Build Completion Notifications
| Condition | Expected |
|-----------|----------|
| Build 1 of 3 completes | Email: "Build 1 of 3 Complete", green header, "NOT final" message |
| Build 2 of 3 completes | Same pattern, mentions "1 remaining" |
| Build 3 of 3 completes | Email: "🎉 All Prints Complete!", cyan header, "ready for pickup" |

### 6.3 Push Notifications
| Condition | Expected |
|-----------|----------|
| Build starts | Push: "🖨️ Build X of Y Started" |
| Build completes (not final) | Push: "✓ Build X of Y Complete" |
| All builds complete | Push: "🎉 All Prints Complete!" |

---

## 7. Snapshots

| Step | Action | Expected |
|------|--------|----------|
| 7.1 | Enable `enable_camera_snapshot` setting | Camera capture enabled |
| 7.2 | Build completes via `poll_builds_status_worker` | Snapshot captured, stored in `build_snapshots` |
| 7.3 | Check `build_snapshots` table | Has `build_id`, `snapshot_data`, `snapshot_type='completion'` |
| 7.4 | Call `get_build_snapshots(build_id)` | Returns snapshot(s) for that build |
| 7.5 | Call `get_request_build_snapshots(request_id)` | Returns all snapshots with build info |
| 7.6 | Build completion email | Includes snapshot if camera enabled |

---

## 8. ETA Accuracy

### 8.1 Single-Build ETA
| Scenario | Expected |
|----------|----------|
| Print at 50% after 30 min | ETA ~60 min total, ~30 min remaining |
| Layer-based (100/200 layers, 30 min elapsed) | ETA ~60 min total |

### 8.2 Multi-Build Request ETA
| Scenario | Expected |
|----------|----------|
| Build 1 of 3 at 50%, 30 min elapsed | "This Build Done" = ~30 min |
| | "All Builds Done" = ~30 min + (2 × avg build time) |
| 2 builds completed (avg 45 min each) | Remaining estimate uses 45 min avg |
| No history, slicer says 120 min total | Per-build estimate = 120/3 = 40 min |

### 8.3 ETA Display
| Context | Display |
|---------|---------|
| Single-build printing | "Est. Completion: Today at 3:45 PM" |
| Multi-build printing | "This Build Done: Today at 2:30 PM" |
| | "All Builds Done: Today at 4:15 PM" |

---

## 9. UI Validation

### 9.1 `/my/{rid}` Page
| Status | Expected UI |
|--------|-------------|
| `APPROVED` (multi-build) | Shows "Build Progress" section with dots |
| `IN_PROGRESS` | Shows build count, completed count, dots |
| `PRINTING` | Shows live progress + "Build X of Y" indicator |
| `BLOCKED` | Shows red dot for failed build, warning |
| `DONE` | Standard completion, optional build snapshots |

### 9.2 Progress Dots
| Build Status | Dot Color |
|--------------|-----------|
| `COMPLETED` | Green (emerald-500) |
| `PRINTING` | Amber (amber-500) + pulse animation |
| `FAILED` | Red (red-500) |
| `READY` | Blue (blue-500) |
| `PENDING` | Gray (zinc-700) |
| `SKIPPED` | Gray (zinc-600) |

---

## 10. Edge Cases

| Case | Test | Expected |
|------|------|----------|
| 0 builds | Request with no files | `total_builds=1` default |
| All builds skipped | Skip all builds | Request → `DONE` |
| Mixed failures | 1 complete, 1 failed, 1 pending | Request → `BLOCKED` |
| Re-approve after failure | Fix failed build, complete all | Request → `DONE` |
| Rapid polling | Multiple poll cycles in quick succession | No duplicate notifications |

---

## Quick Smoke Test Checklist

- [ ] Single-build request works end-to-end
- [ ] Multi-build request shows "Build X of Y" in UI
- [ ] Build completion triggers correct notification (not "all done" until final)
- [ ] Final build triggers "All Prints Complete" notification
- [ ] ETA shows both "This Build Done" and "All Builds Done" for multi-build
- [ ] Failed build shows red dot and request goes to BLOCKED
- [ ] Snapshots are captured and stored per-build
