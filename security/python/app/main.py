import os
import sys
import time
import requests
import psycopg2
import json
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# --- RYCHLÁ KONFIGURACE ---
WAZUH_MIN_LEVEL = 10 
DOCKER_SERVER_IP = "192.168.82.131"

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}", flush=True)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- DB CONFIG ---
DB_HOST = os.getenv('DB_HOST', 'postgres-db')
DB_NAME = os.getenv('DB_NAME', 'soc_data')
DB_USER = os.getenv('DB_USER', 'soc_user')
DB_PASS = os.getenv('DB_PASS', 'SecurityPassword123')

# --- WAZUH CONFIG ---
WAZUH_API_URL = "https://192.168.82.131:55000"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "MyS3cr37P450r.*-"

INDEXER_URL = "https://192.168.82.131:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword"

# --- ZABBIX CONFIG ---
ZABBIX_URL = "http://192.168.82.131:8080/api_jsonrpc.php"
ZABBIX_API_TOKEN = "a9b31ca425a1da42f67d06bb888a112e66a14dd6dd574c87d711b501b980c514"

def get_db_connection():
    while True:
        try:
            conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS, connect_timeout=5)
            return conn
        except Exception as e:
            log(f"Cekam na DB: {e}")
            time.sleep(5)

def init_db():
    log("Inicializace tabulek (v4.2 - Ghost Host Protection)...")
    conn = get_db_connection()
    cur = conn.cursor()
    try:
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
            CREATE TABLE IF NOT EXISTS zabbix_current (
                ip_address VARCHAR(45) PRIMARY KEY,
                status VARCHAR(10),
                cpu_usage FLOAT,
                ram_usage FLOAT,
                disk_usage FLOAT,
                uptime_sec INTEGER,
                last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS zabbix_history (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(45),
                status VARCHAR(10),
                cpu_usage FLOAT,
                ram_usage FLOAT,
                disk_usage FLOAT,
                uptime_sec INTEGER,
                timestamp TIMESTAMP,
                UNIQUE(ip_address, timestamp)
            );
        """)
        conn.commit()
    except Exception as e:
        log(f"CHYBA DB INIT: {e}")
    finally:
        cur.close()
        conn.close()

def fetch_wazuh_data(conn):
    try:
        cur = conn.cursor()
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
                
                ip = a.get('ip', '0.0.0.0')
                if ip in ['127.0.0.1', 'any']: ip = DOCKER_SERVER_IP

                cur.execute("""
                    INSERT INTO hosts (agent_id, ip_address, hostname, os_name, os_version, status)
                    VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (agent_id) 
                    DO UPDATE SET ip_address = EXCLUDED.ip_address, status = EXCLUDED.status, last_update = CURRENT_TIMESTAMP
                """, (a.get('id'), ip, a.get('name'), a.get('os', {}).get('name', 'N/A'), a.get('os', {}).get('version', 'N/A'), a.get('status')))

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
            data = s.get('data', {})
            
            src_ip = data.get('srcip') or s.get('srcip', 'unknown')
            dst_ip = agent.get('ip', '0.0.0.0')
            if dst_ip in ['127.0.0.1', 'any']: dst_ip = DOCKER_SERVER_IP

            cur.execute("""
                INSERT INTO wazuh_alerts (wazuh_id, agent_id, src_ip, dst_ip, alert_level, rule_description, mitre_tactic)
                VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (wazuh_id) DO NOTHING
            """, (hit.get('_id'), agent.get('id'), src_ip, dst_ip, rule.get('level'), 
                  rule.get('description'), (rule.get('mitre', {}).get('tactic') or ['N/A'])[0]))
            
            if cur.rowcount > 0: new_alerts += 1

        conn.commit()
        cur.close()
        log(f"Wazuh OK. Aktivni hoste: {active_count} | Novych alertu: {new_alerts}")

    except Exception as e:
        log(f"CHYBA Wazuh sberu: {e}")

def fetch_zabbix_data(conn):
    try:
        cur = conn.cursor()
        headers = {
            'Content-Type': 'application/json-rpc',
            'Authorization': f'Bearer {ZABBIX_API_TOKEN}'
        }
        
        payload_hosts = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {"output": ["hostid", "name"], "selectInterfaces": ["ip", "available"]},
            "id": 1
        }
        
        res_hosts = requests.post(ZABBIX_URL, json=payload_hosts, headers=headers)
        hosts_data = res_hosts.json().get('result', [])
        metrics_count = 0
        
        for host in hosts_data:
            hostid = host['hostid']
            interfaces = host.get('interfaces', [])
            if not interfaces: continue
            
            host_ip = interfaces[0].get('ip')
            if host_ip == '127.0.0.1': host_ip = DOCKER_SERVER_IP

            avail = str(interfaces[0].get('available', '0'))
            if avail == "1": host_status = "UP"
            elif avail == "2": host_status = "DOWN"
            else: host_status = "UNKNOWN"

            payload_items = {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {"output": ["itemid", "key_", "value_type"], "hostids": hostid},
                "id": 2
            }
            res_items = requests.post(ZABBIX_URL, json=payload_items, headers=headers)
            items = res_items.json().get('result', [])
            
            metrics = {'cpu_usage': 0.0, 'ram_usage': 0.0, 'disk_usage': 0.0, 'uptime_sec': 0}
            latest_clock = 0
            found_any = False
            
            for item in items:
                key = item['key_']
                itemid = item['itemid']
                value_type = int(item['value_type'])
                
                target_metric = None
                if "system.cpu.util" in key: target_metric = 'cpu_usage'
                elif "vm.memory.utilization" in key: target_metric = 'ram_usage'
                elif "vfs.fs.size" in key and "pused" in key: target_metric = 'disk_usage'
                elif "system.uptime" in key: target_metric = 'uptime_sec'
                
                if target_metric:
                    payload_hist = {
                        "jsonrpc": "2.0",
                        "method": "history.get",
                        "params": {
                            "output": "extend",
                            "history": value_type,
                            "itemids": itemid,
                            "sortfield": "clock",
                            "sortorder": "DESC",
                            "limit": 1
                        },
                        "id": 3
                    }
                    res_hist = requests.post(ZABBIX_URL, json=payload_hist, headers=headers)
                    hist_data = res_hist.json().get('result', [])
                    
                    if hist_data:
                        try:
                            val = float(hist_data[0]['value'])
                            clock = int(hist_data[0]['clock'])
                            if clock > latest_clock: latest_clock = clock
                                
                            metrics[target_metric] = round(val, 2) if target_metric != 'uptime_sec' else int(val)
                            found_any = True
                        except ValueError:
                            pass
            
            # --- ZÁPIS DO TABULEK ---
            
            # Ochrana před mrtvými duplicitními hosty (přeskakujeme zápis, pokud nemají data a jsou UNKNOWN)
            if not found_any and host_status == "UNKNOWN":
                continue

            cur.execute("""
                INSERT INTO zabbix_current (ip_address, status, cpu_usage, ram_usage, disk_usage, uptime_sec)
                VALUES (%s, %s, %s, %s, %s, %s) 
                ON CONFLICT (ip_address) 
                DO UPDATE SET status = EXCLUDED.status, cpu_usage = EXCLUDED.cpu_usage, 
                              ram_usage = EXCLUDED.ram_usage, disk_usage = EXCLUDED.disk_usage, 
                              uptime_sec = EXCLUDED.uptime_sec, last_update = CURRENT_TIMESTAMP
            """, (host_ip, host_status, metrics['cpu_usage'], metrics['ram_usage'], metrics['disk_usage'], metrics['uptime_sec']))

            if found_any and latest_clock > 0:
                metric_timestamp = datetime.fromtimestamp(latest_clock).strftime('%Y-%m-%d %H:%M:%S')
                cur.execute("""
                    INSERT INTO zabbix_history (ip_address, status, cpu_usage, ram_usage, disk_usage, uptime_sec, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (ip_address, timestamp) DO NOTHING
                """, (host_ip, host_status, metrics['cpu_usage'], metrics['ram_usage'], metrics['disk_usage'], metrics['uptime_sec'], metric_timestamp))
                
                if cur.rowcount > 0:
                    metrics_count += 1

        conn.commit()
        cur.close()
        log(f"Zabbix OK. Nova historie: {metrics_count} stroju.")

    except Exception as e:
        log(f"CHYBA Zabbix sberu: {e}")

if __name__ == "__main__":
    log("=== SOC INTEGRATOR v4.2 STARTUJE ===")
    init_db()
    while True:
        db_conn = get_db_connection()
        if db_conn:
            fetch_wazuh_data(db_conn)
            fetch_zabbix_data(db_conn)
            db_conn.close()
        time.sleep(60)