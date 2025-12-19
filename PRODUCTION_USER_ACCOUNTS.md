# Production Deployment Guide: User Accounts

This guide covers the steps needed to deploy the user accounts feature to production.

## Prerequisites

Before enabling user accounts in production:

1. **Database Tables**: The auth tables are auto-created on startup, but verify they exist:
   - `users` - User accounts
   - `user_sessions` - Active sessions
   - `admins` - Admin accounts (existing)

2. **Feature Flags**: The system uses feature flags to control feature rollout

## Step-by-Step Deployment

### 1. Enable Feature Flags

Navigate to **Admin → System → Feature Flags** and enable:

| Flag | Description | Recommended |
|------|-------------|-------------|
| `user_accounts` | Master toggle for user account system | Enable first |
| `user_registration` | Allow new user signups | Enable after testing |
| `multi_admin` | Multiple admin accounts with RBAC | Recommended |

### 2. Create Initial Super Admin

If you haven't already set up multi-admin:

1. Go to **Admin → System → Admin Accounts**
2. Current admin password becomes the first Super Admin
3. Create additional admins as needed

### 3. Configure Email (Required for Magic Links)

User accounts rely on magic link authentication. Ensure email is configured:

```env
# Email Configuration (add to .env or environment)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@yourdomain.com
```

**Testing Email:**
1. Go to Admin → Debug
2. Use "Test Email" to verify SMTP works
3. Check spam folders if emails don't arrive

### 4. User Migration Strategy

Existing users with email lookup tokens can be migrated:

#### Automatic Migration (Recommended)
When `user_accounts` is enabled, users visiting "My Prints" with an existing token will see an "Upgrade to Account" modal. This links their existing requests to the new account.

#### Manual Migration (Admin)
1. Go to **Admin → System → User Accounts**
2. Find users who haven't migrated
3. You can manually create accounts and link existing requests

### 5. Security Checklist

Before going live:

- [ ] Strong ADMIN_PASSWORD set (not "admin")
- [ ] HTTPS enabled (required for secure cookies)
- [ ] Email configured and tested
- [ ] Session secret set: `SESSION_SECRET=<random-32-char-string>`
- [ ] Database backups configured

### 6. Environment Variables

Add these to your production environment:

```env
# Required for user accounts
SESSION_SECRET=your-secure-random-string-here
SECRET_KEY=your-api-secret-key-here

# Optional: Session duration (default: 30 days)
SESSION_DURATION_DAYS=30

# Optional: Magic link expiry (default: 24 hours)  
MAGIC_LINK_EXPIRY_HOURS=24
```

## Feature Flag Rollout Strategy

### Phase 1: Admin Testing
1. Enable `user_accounts` flag
2. Keep `user_registration` disabled
3. Test the system with admin-created accounts

### Phase 2: Limited Rollout
1. Enable `user_registration`
2. Use percentage rollout (e.g., 10%)
3. Monitor for issues

### Phase 3: Full Rollout
1. Set rollout to 100%
2. Add "Create Account" CTAs to appropriate pages

## Admin User Management

### User Roles (RBAC)

| Role | Permissions |
|------|-------------|
| **Viewer** | View queue, read-only access |
| **Operator** | Manage queue, approve/reject requests |
| **Admin** | Operator + Store management |
| **Super Admin** | Full access including admin management |

### Managing Users

1. **View Users**: Admin → System → User Accounts
2. **Edit User**: Click edit icon, modify name/email/status/credits
3. **Suspend User**: Prevents login and new requests
4. **Delete User**: Permanent removal (requests remain)
5. **Convert to Admin**: Promotes user to admin role

### User Statuses

| Status | Description |
|--------|-------------|
| `active` | Normal account, can submit requests |
| `unverified` | Email not yet verified |
| `suspended` | Account disabled by admin |

## Troubleshooting

### Users Can't Log In
1. Check `user_accounts` feature flag is enabled
2. Verify email delivery (check spam)
3. Check user status isn't "suspended"

### Migration Modal Not Showing
1. Ensure user has valid email token in localStorage
2. Check `/api/user/check-migration` endpoint
3. Verify `user_accounts` feature is enabled

### Session Issues
1. Clear browser cookies
2. Check SESSION_SECRET is consistent across restarts
3. Verify HTTPS is enabled (secure cookies)

## API Endpoints Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/user/register` | POST | Create new account |
| `/api/user/login` | POST | Password login |
| `/api/user/logout` | POST | End session |
| `/api/user/magic-link` | POST | Request magic link |
| `/api/user/check-migration` | GET | Check if upgrade modal should show |
| `/api/user/migrate-token` | POST | Upgrade token to account |
| `/admin/users` | GET | User management page (admin) |

## Rollback Plan

If issues occur:

1. **Disable Registration**: Turn off `user_registration` flag
2. **Full Disable**: Turn off `user_accounts` flag
3. Users fall back to email token system automatically
4. No data loss - accounts remain in database

## Support

For issues:
- Check Admin → Debug for error logs
- Review Admin → Audit Log for recent changes
- Contact system administrator
