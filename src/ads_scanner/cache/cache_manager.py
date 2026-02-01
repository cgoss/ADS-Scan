"""
Results Cache Manager
SQLite-based caching system for API results with TTL expiration
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from pathlib import Path


class CacheManager:
    """Manages API results cache with TTL"""

    def __init__(self, cache_dir: str, ttl_days: int = 7, enabled: bool = True):
        """
        Initialize cache manager

        Args:
            cache_dir: Directory for cache database
            ttl_days: Time-to-live for cached results in days
            enabled: Whether caching is enabled
        """
        self.cache_dir = Path(cache_dir)
        self.db_path = self.cache_dir / 'results.db'
        self.ttl_days = ttl_days
        self.enabled = enabled

        self.cache_hits = 0
        self.cache_misses = 0

        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._init_database()

    def _init_database(self):
        """Create cache tables if they don't exist"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Create results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_results (
                sha256 TEXT PRIMARY KEY,
                vt_result TEXT,
                ha_result TEXT,
                otx_result TEXT,
                metadefender_result TEXT,
                cached_at TEXT,
                expires_at TEXT
            )
        ''')

        # Create index on expiration
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_expires_at
            ON api_results(expires_at)
        ''')

        conn.commit()
        conn.close()

    def has_result(self, file_hash: str) -> bool:
        """
        Check if hash exists in cache and is not expired

        Args:
            file_hash: SHA256 hash

        Returns:
            True if cached and not expired
        """
        if not self.enabled:
            return False

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        now = datetime.now().isoformat()
        cursor.execute('''
            SELECT sha256 FROM api_results
            WHERE sha256 = ? AND expires_at > ?
        ''', (file_hash, now))

        result = cursor.fetchone()
        conn.close()

        return result is not None

    def get_result(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached result

        Args:
            file_hash: SHA256 hash

        Returns:
            Dictionary with vt_result and ha_result, or None if not found/expired
        """
        if not self.enabled:
            self.cache_misses += 1
            return None

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        now = datetime.now().isoformat()
        cursor.execute('''
            SELECT vt_result, ha_result, otx_result, metadefender_result, cached_at
            FROM api_results
            WHERE sha256 = ? AND expires_at > ?
        ''', (file_hash, now))

        row = cursor.fetchone()
        conn.close()

        if row:
            self.cache_hits += 1
            vt_result = json.loads(row[0]) if row[0] else None
            ha_result = json.loads(row[1]) if row[1] else None
            otx_result = json.loads(row[2]) if row[2] else None
            metadefender_result = json.loads(row[3]) if row[3] else None
            return {
                'vt': vt_result,
                'ha': ha_result,
                'otx': otx_result,
                'metadefender': metadefender_result,
                'cached_at': row[4],
                'from_cache': True
            }
        else:
            self.cache_misses += 1
            return None

    def store_result(self, file_hash: str, results: Dict[str, Any]):
        """
        Store API results in cache

        Args:
            file_hash: SHA256 hash
            results: Dictionary with 'vt' and 'ha' keys containing API results
        """
        if not self.enabled:
            return

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cached_at = datetime.now()
        expires_at = cached_at + timedelta(days=self.ttl_days)

        vt_json = json.dumps(results.get('vt')) if results.get('vt') else None
        ha_json = json.dumps(results.get('ha')) if results.get('ha') else None
        otx_json = json.dumps(results.get('otx')) if results.get('otx') else None
        metadefender_json = json.dumps(results.get('metadefender')) if results.get('metadefender') else None

        # Insert or replace
        cursor.execute('''
            INSERT OR REPLACE INTO api_results
            (sha256, vt_result, ha_result, otx_result, metadefender_result, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_hash,
            vt_json,
            ha_json,
            otx_json,
            metadefender_json,
            cached_at.isoformat(),
            expires_at.isoformat()
        ))

        conn.commit()
        conn.close()

    def prune_expired(self) -> int:
        """
        Remove expired cache entries

        Returns:
            Number of entries removed
        """
        if not self.enabled:
            return 0

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        now = datetime.now().isoformat()
        cursor.execute('DELETE FROM api_results WHERE expires_at <= ?', (now,))

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        return deleted

    def clear_cache(self) -> int:
        """
        Clear all cache entries

        Returns:
            Number of entries removed
        """
        if not self.enabled:
            return 0

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('DELETE FROM api_results')

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        self.cache_hits = 0
        self.cache_misses = 0

        return deleted

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache statistics
        """
        if not self.enabled:
            return {
                'enabled': False,
                'total_entries': 0,
                'expired_entries': 0,
                'cache_hits': 0,
                'cache_misses': 0,
                'hit_rate': 0.0
            }

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Total entries
        cursor.execute('SELECT COUNT(*) FROM api_results')
        total_entries = cursor.fetchone()[0]

        # Expired entries
        now = datetime.now().isoformat()
        cursor.execute('SELECT COUNT(*) FROM api_results WHERE expires_at <= ?', (now,))
        expired_entries = cursor.fetchone()[0]

        conn.close()

        # Calculate hit rate
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = (self.cache_hits / total_requests * 100) if total_requests > 0 else 0.0

        return {
            'enabled': True,
            'total_entries': total_entries,
            'expired_entries': expired_entries,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'hit_rate': f"{hit_rate:.1f}%",
            'ttl_days': self.ttl_days,
            'db_size_mb': self.get_db_size()
        }

    def get_db_size(self) -> float:
        """Get database file size in MB"""
        if not self.enabled or not self.db_path.exists():
            return 0.0

        size_bytes = os.path.getsize(str(self.db_path))
        return size_bytes / (1024 * 1024)

    def optimize_database(self):
        """Run VACUUM to optimize database"""
        if not self.enabled:
            return

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute('VACUUM')
        conn.commit()
        conn.close()

    def __repr__(self) -> str:
        stats = self.get_stats()
        return (
            f"<CacheManager enabled={stats['enabled']} "
            f"entries={stats['total_entries']} "
            f"hits={stats['cache_hits']} "
            f"misses={stats['cache_misses']} "
            f"hit_rate={stats['hit_rate']}>"
        )
