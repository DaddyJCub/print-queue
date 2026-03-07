# Trips Feature - Manual Test Plan

This document outlines manual testing procedures for the private Trips feature.

## Prerequisites

- Two user accounts (User A: trip owner, User B: invited friend)
- Push notifications enabled on at least one device
- Mobile device or browser DevTools mobile emulation for PWA tests
- A sample PDF file for itinerary upload

---

## 1. Trip Creation & Basic Operations

### 1.1 Create a New Trip
1. Log in as User A
2. Navigate to `/trips`
3. Click "New Trip"
4. Fill in:
   - Title: "Test Vegas Trip"
   - Destination: "Las Vegas, NV"
   - Start Date: Tomorrow's date
   - End Date: 3 days from now
   - Timezone: America/Los_Angeles
5. Submit

**Expected:** Trip is created, redirects to trip view page with timeline

### 1.2 Edit Trip Details
1. From trip view, tap menu (⋮) → "Edit Trip"
2. Change destination to "Las Vegas, Nevada"
3. Save

**Expected:** Trip details updated, returns to trip view

### 1.3 View Trip Timeline
1. Verify day-by-day chips are visible and horizontally scrollable
2. Tap different day chips

**Expected:** Page scrolls to corresponding day section

---

## 2. Trip Members & Access Control

### 2.1 Invite a Friend
1. As User A, open trip → Menu → Members
2. Enter User B's email address
3. Select role "Editor"
4. Click "Add Member"

**Expected:** User B appears in members list with "Editor" role

### 2.2 Friend Access Verification
1. Log in as User B
2. Navigate to `/trips`

**Expected:** "Test Vegas Trip" appears in User B's trips list

### 2.3 Non-Member Denial
1. Log in as a third user (or log out User B, create new account)
2. Try to access the trip URL directly: `/trips/{trip_id}`

**Expected:** 403 Forbidden error - "You don't have access to this trip"

### 2.4 PDF Access Denial
1. As non-member, try to access `/trips/{trip_id}/pdf/view`

**Expected:** 403 Forbidden or 401 Unauthorized

---

## 3. Trip Events

### 3.1 Create Events
1. As trip owner, click (+) button to add event
2. Create a flight event:
   - Title: "Flight to Vegas"
   - Category: Flight
   - Date: Trip start date
   - Time: 10:00 AM
   - Flight Number: AA 123
   - From: LAX → To: LAS
   - Reminder: 1 hour before
3. Create a hotel event:
   - Title: "Check in at Bellagio"
   - Category: Hotel
   - Time: 3:00 PM (same day)
   - Location: Bellagio Hotel
   - Confirmation: CONF123456
4. Create an activity:
   - Title: "Dinner at Catch"
   - Category: Meal
   - Time: 7:00 PM
   - Reminder: 30 minutes before

**Expected:** All events appear in timeline under correct day

### 3.2 "What's Next" Display
1. Create an event for the current time + 30 minutes
2. View trip page

**Expected:** "What's Next" card shows the upcoming event with correct time and location

### 3.3 Edit Event
1. Tap on an event to view details
2. Tap edit button
3. Change the time
4. Save

**Expected:** Event updated, reminder_sent reset to allow new reminder

---

## 4. PDF Itinerary Upload

### 4.1 Upload PDF
1. Go to trip menu → "PDF Itinerary"
2. Click upload area
3. Select a PDF file
4. Submit

**Expected:** PDF uploads successfully, preview shows "View PDF" button

### 4.2 View PDF
1. Click "View PDF" button

**Expected:** PDF opens in browser viewer or downloads

### 4.3 PDF Access Control
1. Copy the PDF view URL
2. Log out and try to access URL

**Expected:** Redirects to login or shows 401/403 error

---

## 5. Offline Viewing (PWA)

### 5.1 Cache Trip for Offline
1. Open trip view page while online
2. Navigate through event details
3. Wait a few seconds for caching

### 5.2 Test Offline Mode
1. Enable airplane mode or disconnect network
2. Refresh the trip page

**Expected:**
- Page loads from cache
- "You're offline — viewing cached trip data" banner appears
- Timeline and events are visible (read-only)
- Edit buttons may show errors when tapped

### 5.3 Return Online
1. Reconnect network
2. Refresh page

**Expected:**
- Offline banner disappears
- Full functionality restored

---

## 6. Push Notification Reminders

### 6.1 Enable Notifications
1. Ensure push notifications are enabled for the PWA
2. Verify user has trip reminders enabled in profile (default: on)

### 6.2 Test Reminder Delivery
1. Create a new event with:
   - Time: Current time + 5 minutes
   - Reminder: 5 minutes before
2. Wait for reminder time to pass (server checks every 60 seconds)

**Expected:** Push notification arrives with:
- Title: "Up next: [Event Title]"
- Body: "[Time] • [Location]"

### 6.3 Notification Click-Through
1. When notification appears, tap it

**Expected:**
- App opens to trip view page
- Event is highlighted with a ring animation
- Page scrolls to show the event

### 6.4 Reminder Only Once
1. After reminder fires, check event in database

**Expected:** `reminder_sent = 1` (won't fire again)

### 6.5 Edit Resets Reminder
1. Edit the event and change the time to future
2. Save

**Expected:** `reminder_sent` resets to 0, new reminder will fire

---

## 7. Privacy Verification

### 7.1 No Public Exposure
1. Check public queue page `/queue`

**Expected:** No trip data visible

2. Check browser network tab while viewing `/queue`

**Expected:** No API calls to trip endpoints

### 7.2 Search Engine Protection
1. Check that trips routes are not in sitemap (if any)
2. Verify no trip links appear on public pages

### 7.3 Direct URL Testing
Without authentication, try accessing:
- `/trips` → Should redirect to login
- `/trips/{trip_id}` → Should redirect to login
- `/trips/{trip_id}/events/{event_id}` → Should redirect to login
- `/trips/api/{trip_id}/events` → Should return 401 JSON error

---

## 8. Mobile PWA Experience

### 8.1 Responsive Layout
1. Open trip on mobile device (or DevTools mobile view)
2. Verify:
   - Header fits without overflow
   - Day chips scroll horizontally
   - Events are tappable with adequate touch targets
   - Forms are usable on small screens

### 8.2 Add to Home Screen
1. Use browser "Add to Home Screen" option
2. Launch from home screen icon
3. Navigate to trips

**Expected:** Full standalone app experience, no browser chrome

### 8.3 Sticky "What's Next" Card
1. On mobile, scroll down through timeline
2. Observe "What's Next" card

**Expected:** Card stays visible at top as you scroll

---

## 9. Audit & Security

### 9.1 Check Audit Log
1. As admin, view audit log
2. Look for trip-related actions

**Expected:** Should see entries for:
- TRIP_CREATED
- TRIP_UPDATED
- TRIP_MEMBER_ADDED
- TRIP_MEMBER_REMOVED
- TRIP_EVENT_CREATED

### 9.2 Rate Limiting
1. Rapidly create many events

**Expected:** Should not cause server issues (no specific rate limiting implemented, but should handle gracefully)

---

## Test Results Summary

| Test Section | Status | Notes |
|-------------|--------|-------|
| 1. Trip Creation | ⬜ | |
| 2. Members & Access | ⬜ | |
| 3. Trip Events | ⬜ | |
| 4. PDF Itinerary | ⬜ | |
| 5. Offline Viewing | ⬜ | |
| 6. Push Reminders | ⬜ | |
| 7. Privacy | ⬜ | |
| 8. Mobile PWA | ⬜ | |
| 9. Audit & Security | ⬜ | |

**Legend:** ⬜ Not tested | ✅ Passed | ❌ Failed | ⚠️ Partial

---

## Known Limitations

1. **Timezone Display**: Event times are stored as-is; display timezone is configurable but comparison uses UTC
2. **Offline Edits**: Not supported; requires online connection to modify data
3. **PDF Size**: Large PDFs may take time to upload; no progress indicator
4. **Reminder Precision**: Server checks every 60 seconds, so reminders may be up to 1 minute late
5. **Member Search**: Currently requires exact email match; no autocomplete

---

## Troubleshooting

### Push notifications not working
1. Check browser supports push notifications
2. Verify VAPID keys are configured in environment
3. Check user has push_subscriptions entry in database
4. Check user's notification_prefs includes `trip_reminders_enabled: true`

### Trip page won't load offline
1. Visit trip page while online first (to cache)
2. Ensure service worker is registered (check DevTools → Application → Service Workers)
3. Clear cache and revisit if stale

### "What's Next" shows wrong event
1. Verify event times are in correct format (ISO 8601)
2. Check server time vs local time
3. Events are sorted by start_datetime ascending
