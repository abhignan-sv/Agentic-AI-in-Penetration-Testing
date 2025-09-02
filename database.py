import sqlite3
import json
from datetime import datetime
import os

DB_FILE = "pentest_findings.db"

def init_db():
    """Initialises the SQLite database and creates the 'findings' table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            agent TEXT,
            task TEXT,
            type TEXT, -- e.g., 'recon_data', 'vulnerability', 'exploit_result', 'log_entry'
            data TEXT -- JSON string of the structured data or raw log entry
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exploit_scores (
            module_name TEXT PRIMARY KEY,
            score INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()
    print(f"Database '{DB_FILE}' initialised.")

def insert_finding(agent_name: str, task_name: str, finding_type: str, data: dict | str):
    """Inserts a structured finding or log entry into database.
    'data' can be a dictionary (converted to JSON) or a raw string.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()

    data_to_store = json.dumps(data) if isinstance(data, dict) else str(data)

    cursor.execute(
        "INSERT INTO findings (timestamp, agent, task, type, data) VALUES (?, ?, ?, ?, ?)",
        (timestamp, agent_name, task_name, finding_type, data_to_store)
    ) 
    conn.commit()
    conn.close()

def get_all_findings(target_id: str = None) -> list[dict]:
    """Retrieves all findings from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if target_id:
        cursor.execute("SELECT timestamp, agent, task, type, data FROM findings WHERE target_id = ? ORDER BY timestamp", (target_id,))
    else:
        cursor.execute("SELECT timestamp, agent, task, type, data FROM findings ORDER BY timestamp")
    results = []
    for row in cursor.fetchall():
        try:
            data_dict = json.loads(row[3])
            results.append({
                "agent": row[0],
                "task": row[1],
                "type": row[2],
                "data": data_dict
            })
        except json.JSONDecodeError:
            results.append({
                "agent": row[0],
                "task": row[1],
                "type": row[2],
                "data": row[3]
            })
    conn.close()
    return results

def update_exploit_score(module_name: str, success: bool):
    """Updates the score for an exploit module based on success/failure."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    score_change = 1 if success else -1
    cursor.execute(
        "INSERT OR IGNORE INTO exploit_scores (module_name, score) VALUES (?, 0)",
        (module_name,)
    )
    cursor.execute(
        "UPDATE exploit_scores SET score = score + ? WHERE module_name = ?",
        (score_change, module_name)
    )
    conn.commit()
    conn.close()

def get_exploit_scores(module_name: str = None) -> dict:
    """Retrieves exploit scores, optionally for a specific module."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if module_name:
        cursor.execute("SELECT module_name, score FROM exploit_scores WHERE module_name = ?", (module_name,))
    else:
        cursor.execute("SELECT module_name, score FROM exploit_scores")
    scores = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return scores


def get_targets() -> list[dict]:
    """Retrieves all targets from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, ip_address, hostname, os_type, services, criticality, added_date FROM targets")
    
    targets = []
    for row in cursor.fetchall():
        targets.append({
            "id": row[0],
            "ip_address": row[1],
            "hostname": row[2],
            "os_type": row[3],
            "services": row[4],
            "criticality": row[5],
            "added_date": row[6]
        })
    conn.close()
    return targets

init_db()
