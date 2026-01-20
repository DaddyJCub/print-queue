"""
Migration script: Unified Accounts System

This script migrates data from the legacy users + admins tables
to the new unified accounts table.

Migration strategy:
1. Migrate all admins first (they get elevated roles)
2. Migrate all users (checking for email collisions)
3. For collisions: merge into single account with admin's role, user's preferences
4. Link existing requests to accounts via email matching
5. Create request_assignments for the requester role

Run with: python -m app.migrate_accounts

Options:
  --dry-run     Show what would be migrated without making changes
  --verbose     Show detailed progress
  --force       Skip confirmation prompts
"""

import os
import sys
import sqlite3
import uuid
import json
import argparse
import logging
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Set

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import AccountRole, AdminRole, UserStatus, AssignmentRole
from app.auth import hash_password, db, get_db_path

logger = logging.getLogger("printellect.migration")

# Mapping from legacy AdminRole to new AccountRole
ADMIN_ROLE_MAPPING = {
    "super_admin": AccountRole.OWNER,
    "admin": AccountRole.ADMIN,
    "operator": AccountRole.STAFF,
    "designer": AccountRole.STAFF,
    "viewer": AccountRole.STAFF,  # Viewers become staff with limited permissions
}


class MigrationStats:
    """Track migration statistics."""
    def __init__(self):
        self.admins_migrated = 0
        self.users_migrated = 0
        self.users_merged = 0
        self.requests_linked = 0
        self.assignments_created = 0
        self.errors = []
        self.warnings = []
    
    def summary(self) -> str:
        lines = [
            "=" * 60,
            "MIGRATION SUMMARY",
            "=" * 60,
            f"Admins migrated:      {self.admins_migrated}",
            f"Users migrated:       {self.users_migrated}",
            f"Users merged (collision): {self.users_merged}",
            f"Requests linked:      {self.requests_linked}",
            f"Assignments created:  {self.assignments_created}",
            f"Warnings:             {len(self.warnings)}",
            f"Errors:               {len(self.errors)}",
            "=" * 60,
        ]
        
        if self.warnings:
            lines.append("\nWARNINGS:")
            for w in self.warnings[:10]:  # Show first 10
                lines.append(f"  - {w}")
            if len(self.warnings) > 10:
                lines.append(f"  ... and {len(self.warnings) - 10} more")
        
        if self.errors:
            lines.append("\nERRORS:")
            for e in self.errors[:10]:
                lines.append(f"  - {e}")
            if len(self.errors) > 10:
                lines.append(f"  ... and {len(self.errors) - 10} more")
        
        return "\n".join(lines)


def check_tables_exist(conn: sqlite3.Connection) -> Tuple[bool, bool, bool]:
    """Check which tables exist."""
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users', 'admins', 'accounts')"
    )
    existing = {row[0] for row in cursor.fetchall()}
    return ("users" in existing, "admins" in existing, "accounts" in existing)


def get_legacy_admins(conn: sqlite3.Connection) -> List[Dict]:
    """Get all admins from legacy table."""
    cursor = conn.execute("SELECT * FROM admins ORDER BY created_at")
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_legacy_users(conn: sqlite3.Connection) -> List[Dict]:
    """Get all users from legacy table."""
    cursor = conn.execute("SELECT * FROM users ORDER BY created_at")
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_requests_without_account(conn: sqlite3.Connection) -> List[Dict]:
    """Get requests that don't have an account_id set."""
    cursor = conn.execute("""
        SELECT id, requester_email, requester_name 
        FROM requests 
        WHERE account_id IS NULL OR account_id = ''
    """)
    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def normalize_email(email: str) -> str:
    """Normalize email for consistent matching."""
    return email.lower().strip()


def migrate_admin_to_account(
    conn: sqlite3.Connection, 
    admin: Dict, 
    dry_run: bool = False
) -> Optional[str]:
    """Migrate an admin record to the accounts table."""
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    account_id = str(uuid.uuid4())
    
    # Map role
    legacy_role = admin.get("role", "operator")
    new_role = ADMIN_ROLE_MAPPING.get(legacy_role, AccountRole.STAFF)
    
    # Determine status
    is_active = admin.get("is_active", 1)
    status = UserStatus.ACTIVE.value if is_active else UserStatus.SUSPENDED.value
    
    # Build account data
    account_data = {
        "id": account_id,
        "email": normalize_email(admin["email"]),
        "name": admin.get("display_name") or admin.get("username", "Admin"),
        "role": new_role.value,
        "status": status,
        "password_hash": admin.get("password_hash"),
        "email_verified": 1,  # Admins are assumed verified
        "email_verified_at": now,
        "mfa_secret": admin.get("totp_secret"),
        "mfa_enabled": admin.get("totp_enabled", 0),
        "login_count": admin.get("login_count", 0),
        "last_login": admin.get("last_login"),
        "created_at": admin.get("created_at", now),
        "updated_at": now,
        "migrated_from_admin_id": admin["id"],
    }
    
    if not dry_run:
        columns = ", ".join(account_data.keys())
        placeholders = ", ".join("?" * len(account_data))
        conn.execute(
            f"INSERT INTO accounts ({columns}) VALUES ({placeholders})",
            list(account_data.values())
        )
    
    return account_id


def migrate_user_to_account(
    conn: sqlite3.Connection,
    user: Dict,
    existing_account_id: Optional[str] = None,
    dry_run: bool = False
) -> Tuple[str, bool]:
    """
    Migrate a user record to the accounts table.
    
    If existing_account_id is provided, merge user data into that account.
    Returns (account_id, was_merged).
    """
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    if existing_account_id:
        # Merge: update existing account with user's preferences
        if not dry_run:
            conn.execute("""
                UPDATE accounts SET
                    phone = COALESCE(?, phone),
                    preferred_printer = COALESCE(?, preferred_printer),
                    preferred_material = COALESCE(?, preferred_material),
                    preferred_colors = COALESCE(?, preferred_colors),
                    notes_template = COALESCE(?, notes_template),
                    notification_prefs = COALESCE(?, notification_prefs),
                    avatar_url = COALESCE(?, avatar_url),
                    total_requests = COALESCE(?, 0),
                    total_prints = COALESCE(?, 0),
                    credits = COALESCE(?, 0),
                    migrated_from_user_id = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                user.get("phone"),
                user.get("preferred_printer"),
                user.get("preferred_material"),
                user.get("preferred_colors"),
                user.get("notes_template"),
                user.get("notification_prefs"),
                user.get("avatar_url"),
                user.get("total_requests", 0),
                user.get("total_prints", 0),
                user.get("credits", 0),
                user["id"],
                now,
                existing_account_id
            ))
        return existing_account_id, True
    
    # Create new account from user
    account_id = str(uuid.uuid4())
    
    # Parse notification prefs
    notification_prefs = user.get("notification_prefs", "{}")
    if isinstance(notification_prefs, str):
        try:
            notification_prefs = json.loads(notification_prefs)
        except:
            notification_prefs = {}
    
    account_data = {
        "id": account_id,
        "email": normalize_email(user["email"]),
        "name": user.get("name", ""),
        "role": AccountRole.USER.value,
        "status": user.get("status", UserStatus.UNVERIFIED.value),
        "password_hash": user.get("password_hash"),
        "email_verified": user.get("email_verified", 0),
        "email_verified_at": user.get("email_verified_at"),
        "phone": user.get("phone"),
        "preferred_printer": user.get("preferred_printer"),
        "preferred_material": user.get("preferred_material"),
        "preferred_colors": user.get("preferred_colors"),
        "notes_template": user.get("notes_template"),
        "notification_prefs": json.dumps(notification_prefs) if isinstance(notification_prefs, dict) else notification_prefs,
        "avatar_url": user.get("avatar_url"),
        "total_requests": user.get("total_requests", 0),
        "total_prints": user.get("total_prints", 0),
        "credits": user.get("credits", 0),
        "magic_link_token": user.get("magic_link_token"),
        "magic_link_expires": user.get("magic_link_expires"),
        "reset_token": user.get("reset_token"),
        "reset_token_expires": user.get("reset_token_expires"),
        "last_login": user.get("last_login"),
        "created_at": user.get("created_at", now),
        "updated_at": now,
        "migrated_from_user_id": user["id"],
    }
    
    if not dry_run:
        columns = ", ".join(account_data.keys())
        placeholders = ", ".join("?" * len(account_data))
        conn.execute(
            f"INSERT INTO accounts ({columns}) VALUES ({placeholders})",
            list(account_data.values())
        )
    
    return account_id, False


def link_requests_to_accounts(
    conn: sqlite3.Connection,
    email_to_account: Dict[str, str],
    stats: MigrationStats,
    dry_run: bool = False
) -> None:
    """Link existing requests to accounts and create assignments."""
    requests = get_requests_without_account(conn)
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    
    for req in requests:
        email = normalize_email(req["requester_email"])
        account_id = email_to_account.get(email)
        
        if not account_id:
            stats.warnings.append(f"No account for request {req['id']} (email: {email})")
            continue
        
        if not dry_run:
            # Update request with account_id
            conn.execute(
                "UPDATE requests SET account_id = ? WHERE id = ?",
                (account_id, req["id"])
            )
            
            # Create assignment (requester role)
            assignment_id = str(uuid.uuid4())
            conn.execute("""
                INSERT INTO request_assignments (id, request_id, account_id, role, assigned_at)
                VALUES (?, ?, ?, ?, ?)
            """, (assignment_id, req["id"], account_id, AssignmentRole.REQUESTER.value, now))
            
            stats.assignments_created += 1
        
        stats.requests_linked += 1


def run_migration(dry_run: bool = False, verbose: bool = False) -> MigrationStats:
    """Run the full migration."""
    stats = MigrationStats()
    
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    
    try:
        # Check table existence
        has_users, has_admins, has_accounts = check_tables_exist(conn)
        
        if not has_accounts:
            logger.error("accounts table does not exist. Run app init first.")
            stats.errors.append("accounts table missing")
            return stats
        
        # Email -> account_id mapping for linking requests
        email_to_account: Dict[str, str] = {}
        
        # Step 1: Migrate admins
        if has_admins:
            admins = get_legacy_admins(conn)
            logger.info(f"Migrating {len(admins)} admins...")
            
            for admin in admins:
                try:
                    email = normalize_email(admin["email"])
                    
                    # Check if account already exists (idempotency)
                    existing = conn.execute(
                        "SELECT id FROM accounts WHERE LOWER(email) = ?", (email,)
                    ).fetchone()
                    
                    if existing:
                        email_to_account[email] = existing[0]
                        if verbose:
                            logger.info(f"  Admin {email} already migrated")
                        continue
                    
                    account_id = migrate_admin_to_account(conn, admin, dry_run)
                    email_to_account[email] = account_id
                    stats.admins_migrated += 1
                    
                    if verbose:
                        logger.info(f"  Migrated admin: {email} -> {account_id}")
                
                except Exception as e:
                    stats.errors.append(f"Admin {admin.get('email')}: {e}")
                    logger.error(f"Error migrating admin {admin.get('email')}: {e}")
        
        # Step 2: Migrate users
        if has_users:
            users = get_legacy_users(conn)
            logger.info(f"Migrating {len(users)} users...")
            
            for user in users:
                try:
                    email = normalize_email(user["email"])
                    
                    # Check if account already exists (from admin migration or previous run)
                    existing = conn.execute(
                        "SELECT id FROM accounts WHERE LOWER(email) = ?", (email,)
                    ).fetchone()
                    
                    if existing:
                        # Merge user data into existing account
                        account_id, was_merged = migrate_user_to_account(
                            conn, user, existing[0], dry_run
                        )
                        email_to_account[email] = account_id
                        
                        if was_merged:
                            stats.users_merged += 1
                            if verbose:
                                logger.info(f"  Merged user: {email} into existing account")
                        continue
                    
                    account_id, _ = migrate_user_to_account(conn, user, None, dry_run)
                    email_to_account[email] = account_id
                    stats.users_migrated += 1
                    
                    if verbose:
                        logger.info(f"  Migrated user: {email} -> {account_id}")
                
                except Exception as e:
                    stats.errors.append(f"User {user.get('email')}: {e}")
                    logger.error(f"Error migrating user {user.get('email')}: {e}")
        
        # Step 3: Link requests to accounts
        logger.info("Linking requests to accounts...")
        link_requests_to_accounts(conn, email_to_account, stats, dry_run)
        
        # Commit if not dry run
        if not dry_run:
            conn.commit()
            logger.info("Migration committed successfully")
        else:
            logger.info("DRY RUN - no changes made")
        
    except Exception as e:
        conn.rollback()
        stats.errors.append(f"Migration failed: {e}")
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        conn.close()
    
    return stats


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Migrate to unified accounts system")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--force", "-f", action="store_true", help="Skip confirmation")
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s"
    )
    
    print("=" * 60)
    print("UNIFIED ACCOUNTS MIGRATION")
    print("=" * 60)
    print(f"Database: {get_db_path()}")
    print(f"Dry run: {args.dry_run}")
    print()
    
    if not args.force and not args.dry_run:
        response = input("This will migrate user data. Continue? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return
    
    stats = run_migration(dry_run=args.dry_run, verbose=args.verbose)
    print()
    print(stats.summary())
    
    if stats.errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
