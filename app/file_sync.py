"""
STL Folder Sync Service for Printellect.

Provides:
- Watch folders for new STL/3MF/GCODE files
- Auto-match files to print requests using fuzzy matching
- Move matched files to appropriate folders
- Archive completed prints
"""

import os
import hashlib
import sqlite3
import shutil
import uuid
import re
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from pathlib import Path
from dataclasses import dataclass
import logging
import json
import threading
import time

try:
    from difflib import SequenceMatcher
except ImportError:
    SequenceMatcher = None

from app.models import FileSyncConfig

logger = logging.getLogger("printellect.file_sync")

# ─────────────────────────── DATABASE ───────────────────────────

def get_db_path():
    return os.getenv("DB_PATH", "/data/app.db")

def db():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────── FILE MATCHING ───────────────────────────

def normalize_filename(filename: str) -> str:
    """
    Normalize a filename for matching.
    Removes extension, converts to lowercase, replaces separators with spaces.
    """
    # Remove extension
    name = Path(filename).stem
    
    # Convert to lowercase
    name = name.lower()
    
    # Replace common separators with spaces
    name = re.sub(r'[-_.]', ' ', name)
    
    # Remove multiple spaces
    name = re.sub(r'\s+', ' ', name).strip()
    
    return name


def fuzzy_match_score(str1: str, str2: str) -> float:
    """
    Calculate fuzzy match score between two strings.
    Returns 0.0 to 1.0 (1.0 = exact match).
    """
    if not str1 or not str2:
        return 0.0
    
    # Normalize both strings
    s1 = normalize_filename(str1)
    s2 = normalize_filename(str2)
    
    if s1 == s2:
        return 1.0
    
    # Use SequenceMatcher for fuzzy matching
    if SequenceMatcher:
        return SequenceMatcher(None, s1, s2).ratio()
    
    # Fallback: simple substring matching
    if s1 in s2 or s2 in s1:
        return 0.8
    
    # Check for word overlap
    words1 = set(s1.split())
    words2 = set(s2.split())
    if words1 and words2:
        overlap = len(words1 & words2)
        total = len(words1 | words2)
        return overlap / total
    
    return 0.0


def find_best_match(filename: str, candidates: List[Dict]) -> Optional[Tuple[Dict, float]]:
    """
    Find the best matching candidate for a filename.
    
    Args:
        filename: The file to match
        candidates: List of dicts with 'id' and 'name' fields (requests/builds)
    
    Returns:
        Tuple of (best_match_dict, confidence_score) or None
    """
    if not candidates:
        return None
    
    best_match = None
    best_score = 0.0
    
    normalized_file = normalize_filename(filename)
    
    for candidate in candidates:
        # Try matching against print_name first (most specific)
        if candidate.get('print_name'):
            score = fuzzy_match_score(filename, candidate['print_name'])
            if score > best_score:
                best_score = score
                best_match = candidate
        
        # Try matching against requester name + any notes
        if candidate.get('requester_name'):
            combined = f"{candidate.get('requester_name', '')} {candidate.get('notes', '')}"
            score = fuzzy_match_score(filename, combined)
            if score > best_score:
                best_score = score
                best_match = candidate
        
        # Try matching against existing filenames
        if candidate.get('file_names'):
            for existing_file in candidate['file_names'].split(', '):
                score = fuzzy_match_score(filename, existing_file)
                if score > best_score:
                    best_score = score
                    best_match = candidate
    
    if best_match and best_score > 0:
        return (best_match, best_score)
    
    return None


# ─────────────────────────── FILE OPERATIONS ───────────────────────────

def compute_file_hash(filepath: str) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_file_extension(filename: str) -> str:
    """Get lowercase file extension."""
    return Path(filename).suffix.lower()


def is_valid_extension(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file has an allowed extension."""
    ext = get_file_extension(filename)
    return ext in allowed_extensions


# ─────────────────────────── SYNC CONFIG MANAGEMENT ───────────────────────────

def create_sync_config(
    name: str,
    folder_path: str,
    **kwargs
) -> FileSyncConfig:
    """Create a new file sync configuration."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    config_id = str(uuid.uuid4())
    
    conn.execute("""
        INSERT INTO file_sync_configs 
        (id, name, folder_path, is_active, watch_subfolders, auto_match_requests,
         move_matched_files, archive_completed, match_confidence_threshold,
         allowed_extensions, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        config_id,
        name,
        folder_path,
        1 if kwargs.get('is_active', True) else 0,
        1 if kwargs.get('watch_subfolders', True) else 0,
        1 if kwargs.get('auto_match_requests', True) else 0,
        1 if kwargs.get('move_matched_files', True) else 0,
        1 if kwargs.get('archive_completed', True) else 0,
        kwargs.get('match_confidence_threshold', 0.7),
        json.dumps(kwargs.get('allowed_extensions', [".stl", ".3mf", ".obj", ".gcode"])),
        now,
        now
    ))
    conn.commit()
    conn.close()
    
    logger.info(f"Created sync config: {name} -> {folder_path}")
    return get_sync_config(config_id)


def get_sync_config(config_id: str) -> Optional[FileSyncConfig]:
    """Get sync config by ID."""
    conn = db()
    row = conn.execute("SELECT * FROM file_sync_configs WHERE id = ?", (config_id,)).fetchone()
    conn.close()
    
    if not row:
        return None
    
    return _row_to_sync_config(row)


def get_all_sync_configs() -> List[FileSyncConfig]:
    """Get all sync configurations."""
    conn = db()
    rows = conn.execute("SELECT * FROM file_sync_configs ORDER BY created_at DESC").fetchall()
    conn.close()
    
    return [_row_to_sync_config(row) for row in rows]


def get_active_sync_configs() -> List[FileSyncConfig]:
    """Get only active sync configurations."""
    conn = db()
    rows = conn.execute("SELECT * FROM file_sync_configs WHERE is_active = 1").fetchall()
    conn.close()
    
    return [_row_to_sync_config(row) for row in rows]


def _row_to_sync_config(row: sqlite3.Row) -> FileSyncConfig:
    """Convert database row to FileSyncConfig."""
    allowed_extensions = [".stl", ".3mf", ".obj", ".gcode"]
    try:
        allowed_extensions = json.loads(row["allowed_extensions"] or "[]")
    except:
        pass
    
    return FileSyncConfig(
        id=row["id"],
        name=row["name"],
        folder_path=row["folder_path"],
        is_active=bool(row["is_active"]),
        watch_subfolders=bool(row["watch_subfolders"]),
        auto_match_requests=bool(row["auto_match_requests"]),
        move_matched_files=bool(row["move_matched_files"]),
        archive_completed=bool(row["archive_completed"]),
        match_confidence_threshold=row["match_confidence_threshold"] or 0.7,
        allowed_extensions=allowed_extensions,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_sync_at=row["last_sync_at"],
        total_files_synced=row["total_files_synced"] or 0,
        total_files_matched=row["total_files_matched"] or 0,
    )


def update_sync_config(config_id: str, **kwargs) -> bool:
    """Update sync configuration."""
    allowed_fields = {
        'name', 'folder_path', 'is_active', 'watch_subfolders',
        'auto_match_requests', 'move_matched_files', 'archive_completed',
        'match_confidence_threshold', 'allowed_extensions'
    }
    
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    if not updates:
        return False
    
    # Convert booleans and lists
    for key in ['is_active', 'watch_subfolders', 'auto_match_requests', 
                'move_matched_files', 'archive_completed']:
        if key in updates:
            updates[key] = 1 if updates[key] else 0
    
    if 'allowed_extensions' in updates:
        updates['allowed_extensions'] = json.dumps(updates['allowed_extensions'])
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values())
    values.append(datetime.utcnow().isoformat(timespec="seconds") + "Z")
    values.append(config_id)
    
    conn = db()
    conn.execute(f"UPDATE file_sync_configs SET {set_clause}, updated_at = ? WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return True


def delete_sync_config(config_id: str) -> bool:
    """Delete sync configuration."""
    conn = db()
    conn.execute("DELETE FROM file_sync_configs WHERE id = ?", (config_id,))
    conn.execute("DELETE FROM file_sync_queue WHERE sync_config_id = ?", (config_id,))
    conn.commit()
    conn.close()
    return True


# ─────────────────────────── FILE SYNC QUEUE ───────────────────────────

@dataclass
class SyncQueueItem:
    """Item in the file sync queue."""
    id: str
    sync_config_id: str
    file_path: str
    file_name: str
    file_hash: Optional[str]
    status: str  # pending, matched, ignored, error
    matched_request_id: Optional[str]
    matched_build_id: Optional[str]
    match_confidence: Optional[float]
    created_at: str
    processed_at: Optional[str]


def add_to_sync_queue(
    sync_config_id: str,
    file_path: str,
    file_name: str,
    file_hash: str = None
) -> SyncQueueItem:
    """Add a file to the sync queue."""
    conn = db()
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    item_id = str(uuid.uuid4())
    
    conn.execute("""
        INSERT INTO file_sync_queue 
        (id, sync_config_id, file_path, file_name, file_hash, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (item_id, sync_config_id, file_path, file_name, file_hash, 'pending', now))
    conn.commit()
    conn.close()
    
    return SyncQueueItem(
        id=item_id,
        sync_config_id=sync_config_id,
        file_path=file_path,
        file_name=file_name,
        file_hash=file_hash,
        status='pending',
        matched_request_id=None,
        matched_build_id=None,
        match_confidence=None,
        created_at=now,
        processed_at=None
    )


def get_pending_sync_items(limit: int = 100) -> List[SyncQueueItem]:
    """Get pending items from the sync queue."""
    conn = db()
    rows = conn.execute("""
        SELECT * FROM file_sync_queue 
        WHERE status = 'pending' 
        ORDER BY created_at ASC 
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    
    return [_row_to_sync_item(row) for row in rows]


def _row_to_sync_item(row: sqlite3.Row) -> SyncQueueItem:
    """Convert database row to SyncQueueItem."""
    return SyncQueueItem(
        id=row["id"],
        sync_config_id=row["sync_config_id"],
        file_path=row["file_path"],
        file_name=row["file_name"],
        file_hash=row["file_hash"],
        status=row["status"],
        matched_request_id=row["matched_request_id"],
        matched_build_id=row["matched_build_id"],
        match_confidence=row["match_confidence"],
        created_at=row["created_at"],
        processed_at=row["processed_at"]
    )


def update_sync_item(item_id: str, **kwargs) -> bool:
    """Update a sync queue item."""
    allowed_fields = {'status', 'matched_request_id', 'matched_build_id', 'match_confidence', 'processed_at'}
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    
    if not updates:
        return False
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    values = list(updates.values())
    values.append(item_id)
    
    conn = db()
    conn.execute(f"UPDATE file_sync_queue SET {set_clause} WHERE id = ?", values)
    conn.commit()
    conn.close()
    
    return True


# ─────────────────────────── SYNC OPERATIONS ───────────────────────────

def scan_folder(config: FileSyncConfig) -> List[Dict]:
    """
    Scan a folder for new files to sync.
    Returns list of new files found.
    """
    folder_path = Path(config.folder_path)
    if not folder_path.exists():
        logger.warning(f"Sync folder does not exist: {folder_path}")
        return []
    
    new_files = []
    conn = db()
    
    # Get already-queued file paths
    existing_paths = set()
    rows = conn.execute("""
        SELECT file_path FROM file_sync_queue WHERE sync_config_id = ?
    """, (config.id,)).fetchall()
    for row in rows:
        existing_paths.add(row["file_path"])
    
    # Scan folder
    if config.watch_subfolders:
        files = folder_path.rglob("*")
    else:
        files = folder_path.glob("*")
    
    for file_path in files:
        if not file_path.is_file():
            continue
        
        # Check extension
        if not is_valid_extension(file_path.name, config.allowed_extensions):
            continue
        
        # Skip already queued
        str_path = str(file_path)
        if str_path in existing_paths:
            continue
        
        # Add to queue
        file_hash = compute_file_hash(str_path)
        item = add_to_sync_queue(config.id, str_path, file_path.name, file_hash)
        new_files.append({
            'id': item.id,
            'path': str_path,
            'name': file_path.name,
            'hash': file_hash
        })
        logger.info(f"Found new file: {file_path.name}")
    
    # Update last sync time
    conn.execute("""
        UPDATE file_sync_configs 
        SET last_sync_at = ?, total_files_synced = total_files_synced + ?
        WHERE id = ?
    """, (datetime.utcnow().isoformat(timespec="seconds") + "Z", len(new_files), config.id))
    conn.commit()
    conn.close()
    
    return new_files


def get_matchable_requests() -> List[Dict]:
    """Get requests that could be matched with files."""
    conn = db()
    # Get requests that are in states where they need files
    rows = conn.execute("""
        SELECT 
            r.id, r.requester_name, r.print_name, r.notes, r.status,
            (SELECT GROUP_CONCAT(f.original_filename, ', ') FROM files f WHERE f.request_id = r.id) as file_names
        FROM requests r
        WHERE r.status IN ('NEW', 'APPROVED', 'NEEDS_INFO')
        ORDER BY r.created_at DESC
    """).fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_matchable_builds() -> List[Dict]:
    """Get builds that could be matched with files."""
    conn = db()
    rows = conn.execute("""
        SELECT 
            b.id, b.request_id, b.build_number, b.print_name, b.file_name, b.status,
            r.requester_name, r.notes
        FROM builds b
        JOIN requests r ON b.request_id = r.id
        WHERE b.status IN ('PENDING', 'QUEUED') AND b.file_name IS NULL
        ORDER BY b.created_at DESC
    """).fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def process_pending_matches(config: FileSyncConfig) -> Dict:
    """
    Process pending items and try to auto-match them.
    Returns stats about matches made.
    """
    stats = {
        'processed': 0,
        'matched': 0,
        'unmatched': 0,
        'matches': []
    }
    
    if not config.auto_match_requests:
        return stats
    
    pending_items = get_pending_sync_items()
    if not pending_items:
        return stats
    
    # Get potential matches
    requests = get_matchable_requests()
    builds = get_matchable_builds()
    
    for item in pending_items:
        stats['processed'] += 1
        
        # Try to match against builds first (more specific)
        build_match = find_best_match(item.file_name, builds)
        if build_match and build_match[1] >= config.match_confidence_threshold:
            matched_build, confidence = build_match
            update_sync_item(
                item.id,
                status='matched',
                matched_request_id=matched_build['request_id'],
                matched_build_id=matched_build['id'],
                match_confidence=confidence,
                processed_at=datetime.utcnow().isoformat(timespec="seconds") + "Z"
            )
            stats['matched'] += 1
            stats['matches'].append({
                'file': item.file_name,
                'matched_to': f"Build #{matched_build['build_number']}",
                'request_id': matched_build['request_id'],
                'confidence': confidence
            })
            logger.info(f"Auto-matched {item.file_name} to build {matched_build['id']} ({confidence:.0%})")
            continue
        
        # Try to match against requests
        request_match = find_best_match(item.file_name, requests)
        if request_match and request_match[1] >= config.match_confidence_threshold:
            matched_request, confidence = request_match
            update_sync_item(
                item.id,
                status='matched',
                matched_request_id=matched_request['id'],
                match_confidence=confidence,
                processed_at=datetime.utcnow().isoformat(timespec="seconds") + "Z"
            )
            stats['matched'] += 1
            stats['matches'].append({
                'file': item.file_name,
                'matched_to': matched_request.get('print_name') or matched_request['requester_name'],
                'request_id': matched_request['id'],
                'confidence': confidence
            })
            logger.info(f"Auto-matched {item.file_name} to request {matched_request['id']} ({confidence:.0%})")
            continue
        
        # No match found
        stats['unmatched'] += 1
    
    # Update config stats
    if stats['matched'] > 0:
        conn = db()
        conn.execute("""
            UPDATE file_sync_configs 
            SET total_files_matched = total_files_matched + ?
            WHERE id = ?
        """, (stats['matched'], config.id))
        conn.commit()
        conn.close()
    
    return stats


def run_full_sync(config_id: str = None) -> Dict:
    """
    Run a full sync cycle for one or all configs.
    
    1. Scan folders for new files
    2. Process pending matches
    3. Return stats
    """
    results = {
        'configs_processed': 0,
        'new_files': 0,
        'matches_made': 0,
        'details': []
    }
    
    if config_id:
        configs = [get_sync_config(config_id)]
        configs = [c for c in configs if c]
    else:
        configs = get_active_sync_configs()
    
    for config in configs:
        result = {
            'config_id': config.id,
            'config_name': config.name,
            'new_files': [],
            'matches': []
        }
        
        # Scan for new files
        new_files = scan_folder(config)
        result['new_files'] = new_files
        results['new_files'] += len(new_files)
        
        # Process matches
        match_stats = process_pending_matches(config)
        result['matches'] = match_stats.get('matches', [])
        results['matches_made'] += match_stats.get('matched', 0)
        
        results['details'].append(result)
        results['configs_processed'] += 1
    
    return results


# ─────────────────────────── BACKGROUND WATCHER ───────────────────────────

class FolderWatcher:
    """
    Background service that watches folders for new files.
    Uses polling (vs filesystem events) for cross-platform compatibility.
    """
    
    def __init__(self, poll_interval: int = 30):
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread = None
        self._running = False
    
    def start(self):
        """Start the background watcher."""
        if self._running:
            return
        
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()
        self._running = True
        logger.info("Folder watcher started")
    
    def stop(self):
        """Stop the background watcher."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("Folder watcher stopped")
    
    def _watch_loop(self):
        """Main watch loop."""
        while not self._stop_event.is_set():
            try:
                configs = get_active_sync_configs()
                for config in configs:
                    if self._stop_event.is_set():
                        break
                    
                    # Scan and process
                    scan_folder(config)
                    process_pending_matches(config)
                
            except Exception as e:
                logger.error(f"Error in folder watcher: {e}")
            
            # Wait for next poll
            self._stop_event.wait(self.poll_interval)
    
    @property
    def is_running(self) -> bool:
        return self._running


# Global watcher instance
_watcher: Optional[FolderWatcher] = None

def get_watcher() -> FolderWatcher:
    """Get or create the global folder watcher."""
    global _watcher
    if _watcher is None:
        _watcher = FolderWatcher()
    return _watcher


def start_watcher():
    """Start the global folder watcher."""
    watcher = get_watcher()
    watcher.start()


def stop_watcher():
    """Stop the global folder watcher."""
    if _watcher:
        _watcher.stop()


# ─────────────────────────── ADMIN API FUNCTIONS ───────────────────────────

def get_pending_matches(limit: int = 50) -> List[Dict]:
    """
    Get pending file matches awaiting review/approval.
    Returns list of match candidates for admin UI.
    """
    conn = db()
    rows = conn.execute("""
        SELECT 
            q.id,
            q.config_id,
            q.file_name,
            q.file_path,
            q.matched_request_id,
            q.matched_build_id,
            q.match_confidence,
            q.status,
            r.print_name as request_name,
            r.requester_name
        FROM file_sync_queue q
        LEFT JOIN requests r ON q.matched_request_id = r.id
        WHERE q.status = 'matched' AND q.match_confidence < 0.9
        ORDER BY q.discovered_at DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    
    return [{
        'id': row['id'],
        'request_id': row['matched_request_id'],
        'request_name': row['request_name'] or row['requester_name'] or 'Unknown',
        'matched_filename': row['file_name'],
        'matched_filepath': row['file_path'],
        'confidence': row['match_confidence'] or 0,
        'status': row['status']
    } for row in rows]


def get_sync_stats() -> Dict:
    """Get overall sync statistics for admin dashboard."""
    conn = db()
    
    # Count folders
    folder_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM file_sync_configs"
    ).fetchone()['cnt']
    
    # Count indexed files
    file_count = conn.execute(
        "SELECT SUM(total_files_scanned) as cnt FROM file_sync_configs"
    ).fetchone()['cnt'] or 0
    
    # Count pending matches
    pending_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM file_sync_queue WHERE status = 'matched' AND match_confidence < 0.9"
    ).fetchone()['cnt']
    
    # Count auto-matched
    auto_matched = conn.execute(
        "SELECT COUNT(*) as cnt FROM file_sync_queue WHERE status = 'attached'"
    ).fetchone()['cnt']
    
    conn.close()
    
    return {
        'total_folders': folder_count,
        'total_files': file_count,
        'pending_matches': pending_count,
        'auto_matched': auto_matched
    }


def sync_folder(folder_id: str) -> Dict:
    """
    Trigger sync for a single folder by ID.
    Returns sync results.
    """
    config = get_sync_config(folder_id)
    if not config:
        return {'error': 'Folder not found', 'files_found': 0}
    
    new_files = scan_folder(config)
    match_stats = process_pending_matches(config)
    
    return {
        'files_found': len(new_files),
        'matches_made': match_stats.get('matched', 0),
        'new_files': new_files
    }


def approve_file_match(match_id: str) -> bool:
    """
    Approve a pending file match and attach the file to the request.
    """
    conn = db()
    
    # Get the match details
    row = conn.execute("""
        SELECT * FROM file_sync_queue WHERE id = ?
    """, (match_id,)).fetchone()
    
    if not row:
        conn.close()
        return False
    
    # Update the match status
    conn.execute("""
        UPDATE file_sync_queue 
        SET status = 'attached', processed_at = ?
        WHERE id = ?
    """, (datetime.utcnow().isoformat(timespec="seconds") + "Z", match_id))
    
    # If there's a request ID, update the request with the file
    if row['matched_request_id']:
        # Add the file to the request's uploads or notes
        conn.execute("""
            UPDATE requests 
            SET notes = COALESCE(notes, '') || '\n\n[Auto-matched file: ' || ? || ']'
            WHERE id = ?
        """, (row['file_path'], row['matched_request_id']))
    
    conn.commit()
    conn.close()
    return True


def reject_file_match(match_id: str) -> bool:
    """
    Reject a pending file match.
    """
    conn = db()
    conn.execute("""
        UPDATE file_sync_queue 
        SET status = 'rejected', processed_at = ?
        WHERE id = ?
    """, (datetime.utcnow().isoformat(timespec="seconds") + "Z", match_id))
    conn.commit()
    conn.close()
    return True

