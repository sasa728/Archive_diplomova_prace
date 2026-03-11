import os
import sys
import time
import requests
import psycopg2
import json
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# --- KONFIGURACE ---
WAZUH_MIN_LEVEL = 10 

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}", flush=True)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- CONFIG ---
DB_HOST = os.getenv('DB_HOST', 'postgres-db')
DB_NAME = os.getenv('DB_NAME', 'soc_data')
DB_USER = os.getenv('DB_USER', 'soc_user')
DB_PASS = os.getenv('DB_PASS', 'SecurityPassword123')

WAZUH_API_URL = "https://192.168.82.131:55000"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "MyS3cr37P450r.*-"

INDEXER_URL = "https://192.168.82.131:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword"

def get_db_connection():
    while True:
        try:
            conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS, connect_timeout=5)
            return conn
        except Exception as e:
            log(f"Cekam na DB: {e}")
            time.sleep(5)

def init_db():
    log("Inicializace tabulek (v2.0 - Full Incident Data)...")
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # 1. Tabulka hosts (Cílové servery)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                agent_id VARCHAR(10) PRIMARY KEY,
                ip_address VARCHAR(45),
                hostname VARCHAR(255),
                os_name VARCHAR(100),
                os_version VARCHAR(100),
                status VARCHAR(20),
                last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # 2. Tabulka wazuh_alerts (Incidenty se Zdrojem i Cílem)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS wazuh_alerts (
                id SERIAL PRIMARY KEY,
                wazuh_id VARCHAR(100) UNIQUE,
                agent_id VARCHAR(10) REFERENCES hosts(agent_id),
                src_ip VARCHAR(45),
                dst_ip VARCHAR(45),
                alert_level INTEGER,
                rule_description TEXT,
                mitre_tactic VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        log("Tabulky jsou pripraveny.")
    except Exception as e:
        log(f"CHYBA DB INIT: {e}")
    finally:
        cur.close()
        conn.close()

def fetch_data():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # --- 1. SBER AGENTU ---
        r_auth = requests.post(f"{WAZUH_API_URL}/security/user/authenticate", 
                               auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
        token = r_auth.json().get('data', {}).get('token')
        
        active_count = 0
        if token:
            r_agents = requests.get(f"{WAZUH_API_URL}/agents", 
                                    headers={'Authorization': f'Bearer {token}'}, verify=False)
            agents = r_agents.json().get('data', {}).get('affected_items', [])
            for a in agents:
                if a.get('status') == 'active': active_count += 1
                cur.execute("""
                    INSERT INTO hosts (agent_id, ip_address, hostname, os_name, os_version, status)
                    VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (agent_id) 
                    DO UPDATE SET status = EXCLUDED.status, last_update = CURRENT_TIMESTAMP, ip_address = EXCLUDED.ip_address
                """, (a.get('id'), a.get('ip'), a.get('name'), a.get('os', {}).get('name'), a.get('os', {}).get('version'), a.get('status')))

        # --- 2. SBER ALERTU (Indexer) ---
        query = {
            "size": 100,
            "sort": [{"timestamp": "desc"}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": WAZUH_MIN_LEVEL}}},
                        {"range": {"timestamp": {"gte": "now-1m"}}}
                    ]
                }
            }
        }
        
        r_indexer = requests.get(f"{INDEXER_URL}/wazuh-alerts-*/_search", 
                                 auth=(INDEXER_USER, INDEXER_PASS), 
                                 headers={"Content-Type": "application/json"},
                                 data=json.dumps(query), verify=False)
        
        hits = r_indexer.json().get('hits', {}).get('hits', [])
        new_alerts = 0
        for hit in hits:
            s = hit.get('_source', {})
            rule = s.get('rule', {})
            agent = s.get('agent', {})
            data = s.get('data', {}) # Tady byva zdrojova IP
            
            # Zdrojova IP (attacker) - Wazuh ji miva v data.srcip nebo prime v srcip
            src_ip = data.get('srcip') or s.get('srcip', 'unknown')
            # Cilova IP (victim) - to je IP agenta
            dst_ip = agent.get('ip', '0.0.0.0')

            cur.execute("""
                INSERT INTO wazuh_alerts (wazuh_id, agent_id, src_ip, dst_ip, alert_level, rule_description, mitre_tactic)
                VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (wazuh_id) DO NOTHING
            """, (hit.get('_id'), agent.get('id'), src_ip, dst_ip, rule.get('level'), 
                  rule.get('description'), (rule.get('mitre', {}).get('tactic') or ['N/A'])[0]))
            
            if cur.rowcount > 0: new_alerts += 1

        conn.commit()
        cur.close()
        conn.close()
        log(f"Sber OK. Aktivni hoste: {active_count} | Novych alertu: {new_alerts}")

    except Exception as e:
        log(f"CHYBA Sberu: {e}")

if __name__ == "__main__":
    log("=== SOC INTEGRATOR v2.0 STARTUJE ===")
    init_db()
    while True:
        fetch_data()
        time.sleep(60)