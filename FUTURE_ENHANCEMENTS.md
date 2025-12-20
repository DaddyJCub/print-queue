# Printellect Future Enhancements Roadmap

**Last Updated:** December 19, 2025  
**Current Version:** 0.10.0

This document tracks planned enhancements and improvements for Printellect. Items are organized by priority and category. Check items off as they are completed.

---

## ✅ Recently Completed

### v0.10.0 (2025-12-19)
- [x] **Settings Tabs Interface** - Unified tabbed navigation for all settings pages
- [x] **Fixed 500 errors** - Audit Log (localtime filter), File Sync (column name typo)
- [x] **Consistent layouts** - Removed double-header issues on settings sub-pages

### v0.9.0 (2025-12-19)
- [x] **Admin tab in PWA** - 5th tab in bottom nav when logged in as admin
- [x] **Unified admin navigation** - Bottom nav on admin pages matching public pages
- [x] **My Prints pagination** - Show 3 items by default with "Show more"
- [x] **Collapsible Past Prints** - Picked up, rejected, cancelled in collapsible section

---

## 🔴 High Priority

### Navigation & Layout
- [ ] **Admin Navigation Restructure** - Group nav items into dropdowns (Content, Settings)
- [ ] **Breadcrumbs** - Add breadcrumbs on nested admin pages for context
- [ ] **Route Simplification** - Consolidate `/my-requests` + `/my-requests/view` into smart redirect

### PWA Improvements  
- [ ] **Offline State Banner** - Show banner when offline with cached data indicator
- [ ] **SW Update Toast** - Notify users when new version is available
- [ ] **Smart Install Prompt** - Single prompt after engagement (3+ page views)
- [ ] **Loading Skeleton States** - Add skeleton loaders for queue, dashboard

### Error Handling
- [ ] **Global Error Boundary** - Consistent error handling across all pages
- [ ] **Helpful Error Messages** - Replace "please refresh" with actionable messages
- [ ] **Retry Actions** - Add retry buttons on failed operations

---

## 🟠 Medium Priority

### Template Cleanup
- [ ] **Delete Old Templates** - Remove `request_form.html`, `public_queue.html`, `my_requests_lookup.html`, etc.
- [ ] **Rename _new Templates** - Rename `*_new.html` to standard names
- [ ] **Create Component Library** - Shared partials in `_components/`:
  - [ ] `status_badge.html` - Standardized status badges
  - [ ] `printer_card.html` - Consolidated printer status cards
  - [ ] `loading_spinner.html` - Consistent loading indicator
  - [ ] `empty_state.html` - Empty state messaging
  - [ ] `error_toast.html` - Error notification component

### State & Feedback
- [ ] **Toast Notification System** - Global toast component for success/error/info
- [ ] **Loading States for Forms** - Spinner overlay on form submission
- [ ] **Optimistic Updates** - Immediate UI feedback before server response
- [ ] **Background Activity Indicator** - Show push notification status

### Admin Features
- [ ] **Destructive Action Styling** - Red styling + confirmation for reject/delete
- [ ] **Admin vs User Error Detail** - Technical details for admins, friendly for users
- [ ] **Quick Filters** - Filter queue by printer, status

---

## 🟡 Lower Priority

### Visual Polish
- [ ] **Standardize Border Radius** - `rounded-xl` for cards, `rounded-lg` for buttons
- [ ] **Icon Sizing Standards** - 20px inline, 24px nav, 32px hero
- [ ] **Touch Target Audit** - Ensure 44x44px minimum on all interactive elements
- [ ] **Reduce Emoji Overuse** - Keep emojis in headers only, not functional elements

### Authentication
- [ ] **Auth Context Clarification** - Help users understand admin cookie vs request token vs magic link
- [ ] **Session Sync UX** - Simplify 6-digit code workflow

### Performance
- [ ] **Lazy Load Images** - Add loading="lazy" to non-critical images
- [ ] **Optimize Polling** - Reduce API call frequency when tab is background
- [ ] **Cache Strategy Audit** - Review SW caching for optimal offline experience

---

## 💡 Ideas / Future Consideration

### User Experience
- [ ] **Request Templates** - Save common request configurations for reuse
- [ ] **Bulk Request Upload** - Upload multiple files for batch requests
- [ ] **Status Explanation Tooltips** - Help first-time users understand statuses
- [ ] **Progress Photos** - Admin can attach in-progress photos to requests

### Admin Tools
- [ ] **Admin Dashboard Widgets** - Customizable dashboard layout
- [ ] **Scheduled Status Changes** - Set status to change at future time
- [ ] **Request Assignment** - Assign requests to specific admin users
- [ ] **Printer Groups** - Group printers by type or location

### Integrations
- [ ] **Webhook Notifications** - Send events to external services
- [ ] **Discord/Slack Integration** - Post updates to chat channels
- [ ] **Slicer Integration** - Auto-import print time from slicer exports
- [ ] **Calendar Integration** - Sync pickup times to Google/Outlook calendar

### Analytics
- [ ] **Custom Date Ranges** - Select date range for analytics
- [ ] **Export Reports** - Download analytics as CSV/PDF
- [ ] **Printer Utilization Graphs** - Visual timeline of printer usage
- [ ] **Requester Statistics** - Track repeat requesters

---

## Implementation Notes

### When Starting a New Feature

1. Check this file for context and related items
2. Update version in `app/main.py` following semver:
   - `0.X.0` for new features
   - `0.x.Y` for bug fixes
3. Add changelog entry in `app/main.py` header comments
4. Add changelog entry in `app/templates/changelog.html`
5. Mark item complete in this file with completion date

### Testing Checklist

Before marking a feature complete:
- [ ] Works on desktop Chrome, Firefox, Safari
- [ ] Works on mobile (iOS Safari, Android Chrome)
- [ ] Works in PWA mode (installed app)
- [ ] Works offline (if applicable)
- [ ] No console errors
- [ ] No 500 errors in server logs
- [ ] Responsive at all breakpoints

### Files Commonly Modified

| Area | Files |
|------|-------|
| Version | `app/main.py` (line ~32) |
| Changelog | `app/templates/changelog.html` |
| Navigation | `app/templates/admin_nav.html`, `app/templates/pwa_base.html` |
| Components | `app/templates/_components/` |
| Routes | `app/main.py`, `app/routes_auth.py` |
| Styles | Inline Tailwind in templates |

---

## References

- [UX_REDESIGN_REPORT.md](UX_REDESIGN_REPORT.md) - Detailed UX audit and recommendations
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Testing procedures
- [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) - Development setup
