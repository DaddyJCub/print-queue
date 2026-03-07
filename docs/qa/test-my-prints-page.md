# My Prints Page - Quick Test Script

**URL:** `http://localhost:8000/my-requests/demo`

---

## 1. Account Menu (30 sec)
- [ ] Click avatar button (top-right, shows first letter)
- [ ] Menu opens with: email, Notification Settings, Sync to App, Send Feedback, Sign Out
- [ ] Click outside menu → closes
- [ ] Click avatar again → reopens

## 2. Notification Settings Modal (1 min)
- [ ] Open account menu → click "🔔 Notification Settings"
- [ ] Modal slides up (mobile) or centers (desktop)
- [ ] **Email toggle**: Click to toggle ON/OFF, shows toast message
- [ ] **Push toggle**: Shows status (likely "Not supported" or "Not enabled" in localhost)
- [ ] Click X or outside modal → closes

## 3. Sync to App Modal (30 sec)
- [ ] Open account menu → click "📱 Sync to App"
- [ ] Shows 6-digit code (or "Error" if API not running)
- [ ] Timer counts down
- [ ] "New Code" button works
- [ ] "Done" closes modal

## 4. Print Queue Display (30 sec)
- [ ] **DONE** requests show cyan badge
- [ ] **PRINTING** request shows amber badge + progress bar (67%)
- [ ] **NEEDS_INFO** shows orange badge + warning text
- [ ] **APPROVED** shows emerald badge
- [ ] **NEW** shows blue badge
- [ ] Requests sorted: DONE → PRINTING → NEEDS_INFO → others

## 5. Mobile Responsiveness (30 sec)
- [ ] Resize browser to mobile width (~375px)
- [ ] Account avatar still clickable
- [ ] Modals slide up from bottom
- [ ] All content readable

---

## Quick Pass/Fail

| Feature | Status |
|---------|--------|
| Account menu opens/closes | ⬜ |
| Notification modal opens | ⬜ |
| Email toggle works | ⬜ |
| Push status displays | ⬜ |
| Sync modal shows code | ⬜ |
| Status badges correct colors | ⬜ |
| Progress bar visible | ⬜ |

**Total test time: ~3 minutes**
