# Print Timer Feature - Quick Test Guide

## Prerequisites
- App running and accessible at `http://localhost:8000`
- At least 2 test requests in the database (different statuses)
- Admin password configured

## Test Scenario 1: Print Timer Countdown

### Setup
1. Create 2 test requests via `/` form (names: "Test1", "Test2")
2. Log in to admin (`/admin/login`)
3. Go to dashboard (`/admin`)
4. Approve Request 1
5. Change Request 1 status to PRINTING (without comment)

### Set Print Time
1. Click on Request 1 detail link
2. Scroll down to **"Print Time Estimate"** section (emerald-green box)
3. Enter:
   - Hours: **2**
   - Minutes: **45**
   - Turnaround: **30** (default)
4. Click **"💾 Save print time"** button
5. Page should reload and show "⏱ 2h 45m" in the Print Time Estimate header

### View Live Countdown
1. Open public queue page: `/queue`
2. Find the PRINTING request (should be Request 1)
3. Look at the **"Time"** column (rightmost)
4. Should show **"02:45:30"** (HH:MM:SS format)
5. Watch it count down (decrements every 1 second)
6. After ~10 seconds, should see **"02:45:20"** etc.

### Verify Auto-Refresh
1. Let countdown reach "00:00:05"
2. Watch it complete to "00:00:00"
3. Should change to **"Done! ✓"** (amber color)
4. Page should auto-refresh within 3 seconds
5. Request status should update to reflect next print

---

## Test Scenario 2: Queue Wait Prediction with Turnaround

### Setup
1. Create 4 test requests (names: "Print-A", "Print-B", "Print-C", "Print-D")
2. In admin dashboard:
   - Print-A: Set to PRINTING, print time: **1h 0m**, turnaround: **15m**
   - Print-B: Set to APPROVED, print time: **2h 0m**, turnaround: **20m**
   - Print-C: Set to APPROVED, print time: **3h 0m**, turnaround: **30m**
   - Print-D: Set to NEW (no print time yet)

### Verify Wait Time Calculations
1. Go to public queue: `/queue`
2. Find Print-A (PRINTING):
   - Time column should show countdown at **01:00:XX**
3. Find Print-B (APPROVED, position 2):
   - Time column should show: **"Est. 0h 20m"**
   - Calculation: 15m (turnaround from A) + 0m (A done) = 15m... wait, should be 20m (turnaround_minutes for B itself)
   - Actually: 15m (turnaround between A→B) = "Est. 0h 15m"
4. Find Print-C (APPROVED, position 3):
   - Time column should show: **"Est. 2h 35m"**
   - Calculation: 15m (A→B turnaround) + 2h (Print-B) + 20m (B→C turnaround) = 2h 35m
5. Find Print-D (NEW):
   - Time column should show: **"—"** (no estimate)

### Change Turnaround Time
1. Go to Print-B detail page
2. In Print Time Estimate section:
   - Change Hours to **2**
   - Change Minutes to **30**
   - Change Turnaround to **60** (1 hour)
3. Click **"💾 Save print time"**
4. Return to public queue
5. Print-C estimate should update:
   - New calc: 15m + 2.5h + 60m = **4h 15m** (was 2h 35m)

---

## Test Scenario 3: Mobile Responsiveness

### Desktop View (>768px)
1. Open `/queue` on full-width browser
2. Table should show all columns clearly
3. Countdown timer should be readable in the Time column
4. Status badges and notes should display properly

### Mobile View (<768px)
1. Open `/queue` on mobile device or narrow window (<600px)
2. Table should become scrollable horizontally
3. **Important columns (ID, Status, Time) should remain visible**
4. Countdown timer should still update correctly
5. Test landscape mode - verify table doesn't break

---

## Test Scenario 4: Edge Cases

### No Print Time Set
1. Create request, approve it, but don't set print time
2. Go to public queue
3. Time column should show **"—"** (not error, not empty, not crash)

### Zero Minutes
1. In Print Time Estimate: Hours=0, Minutes=0
2. Try to save
3. Should show validation error: "Print time must be at least 1 minute"

### Maximum Time
1. In Print Time Estimate: Hours=999, Minutes=59
2. Click save
3. Should accept and convert to 59,999 minutes
4. Countdown should still work (will take 41+ days to count down, but shouldn't error)

### Turnaround Edge Cases
- Set Turnaround to 0: Next print starts immediately
- Set Turnaround to 1440 (24h): Next print delayed by full day
- Both should calculate correctly in wait estimates

---

## Test Scenario 5: Admin Request Detail Page

### Print Time Form Verification
1. Go to admin request detail for Request 1
2. Scroll to **"Print Time Estimate"** section (emerald box)
3. Verify form has:
   - Hours input (0-999)
   - Minutes input (0-59)
   - Turnaround input (0-1440)
   - **"💾 Save print time"** button
4. If request has print time set:
   - Should display "⏱ Xh Ym" badge in top right of section

### Form Persistence
1. Set Hours: 1, Minutes: 30, Turnaround: 45
2. Save
3. Reload page
4. Form should show previous values (not reset)

---

## Test Scenario 6: Full User Journey

### Requester Perspective
1. Submit print request via `/`
2. Redirected to `/queue?mine={8-char-id}`
3. See "Your Position" card:
   - Request ID shown
   - Position #4 (example)
   - Total active count: 5
4. Mark position for easy reference

### Admin Perspective (Next Day)
1. Open admin dashboard
2. Review new requests
3. Approve request 1, set to PRINTING
4. Open request 1 detail
5. Set print time: 2h 45m, turnaround: 30m
6. Save

### Public Sees It Immediately
1. Refresh `/queue` page (or view in another browser)
2. See countdown timer for PRINTING request
3. See estimated wait times for all APPROVED requests
4. Watch countdown tick down in real-time

---

## Debugging Tips

### Countdown Not Showing
- Check browser console for JavaScript errors
- Verify `data-timer` attribute on element
- Check `data-minutes` has valid number

### Wait Times Wrong
- Verify print_time_minutes is saved in database
- Check request ordering (by created_at ASC)
- Remember: only counts requests AHEAD in queue

### Page Not Auto-Refreshing
- Check browser console
- Verify JavaScript runs without errors
- May need to manually refresh if JavaScript is blocked

### Database Issues
- Check SQLite file exists at DB_PATH
- Run migrations by restarting app
- View with: `sqlite3 print_queue.db "PRAGMA table_info(requests);"`

---

## Success Indicators

✅ Countdown timer appears and decrements\
✅ Wait estimates shown for APPROVED requests\
✅ Turnaround time factored into calculations\
✅ "Done! ✓" shown when countdown reaches 0\
✅ Page auto-refreshes on countdown complete\
✅ Mobile view remains responsive\
✅ Form validates input correctly\
✅ Data persists across page reloads\
✅ No JavaScript errors in console\
✅ No database errors in server logs\

