import os
import sys
import time
import requests
import psycopg2
import json
import socket
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib3.exceptions import InsecureRequestWarning

# --- RYCHLÁ KONFIGURACE ---
WAZUH_MIN_LEVEL = 10 
DOCKER_SERVER_IP = "192.168.82.131"
RETENTION_DAYS = 30  # Počet dní, po kterých se smaže historie z Wazuhu a Zabbixu

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

# --- GREENBONE CONFIG ---
GREENBONE_HOST = "192.168.82.131"
GREENBONE_PORT = 9390
GREENBONE_USER = "admin"
GREENBONE_PASS = "admin"

def get_db_connection():
    while True:
        try:
            conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS, connect_timeout=5)
            return conn
        except Exception as e:
            log(f"Cekam na DB: {e}")
            time.sleep(5)

def init_db():
    log(f"Inicializace tabulek (v5.9.0 - Pridano MITRE, CTI a CVE)...")
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
                mitre_technique VARCHAR(100),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS zabbix_current (
                ip_address VARCHAR(45) PRIMARY KEY,
                status VARCHAR(10),
                os_info VARCHAR(255),
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
                os_info VARCHAR(255),
                cpu_usage FLOAT,
                ram_usage FLOAT,
                disk_usage FLOAT,
                uptime_sec INTEGER,
                timestamp TIMESTAMP,
                UNIQUE(ip_address, timestamp)
            );
            CREATE TABLE IF NOT EXISTS greenbone_vulns (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(45),
                nvt_name TEXT,
                threat_level VARCHAR(100),
                cvss FLOAT,
                port VARCHAR(100),
                cve TEXT, -- PŘIDÁNO
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip_address, nvt_name, port)
            );
        """)
        cur.execute("ALTER TABLE zabbix_current ADD COLUMN IF NOT EXISTS os_info VARCHAR(255);")
        cur.execute("ALTER TABLE zabbix_history ADD COLUMN IF NOT EXISTS os_info VARCHAR(255);")
        cur.execute("ALTER TABLE wazuh_alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(100);")
        cur.execute("ALTER TABLE greenbone_vulns ADD COLUMN IF NOT EXISTS cve TEXT;") # PŘIDÁNO
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

            # PŘIDÁNO: Vytěžení MITRE techniky i taktiky
            mitre_tactic = (rule.get('mitre', {}).get('tactic') or ['N/A'])[0]
            mitre_technique = (rule.get('mitre', {}).get('id') or ['N/A'])[0]

            cur.execute("""
                INSERT INTO wazuh_alerts (wazuh_id, agent_id, src_ip, dst_ip, alert_level, rule_description, mitre_tactic, mitre_technique)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (wazuh_id) DO NOTHING
            """, (hit.get('_id'), agent.get('id'), src_ip, dst_ip, rule.get('level'), 
                  rule.get('description'), mitre_tactic, mitre_technique))
            
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
            "params": {
                "output": ["hostid", "name"], 
                "selectInterfaces": ["ip", "available"], 
                "selectInventory": ["os", "os_full", "software"]
            },
            "id": 1
        }
        
        res_hosts = requests.post(ZABBIX_URL, json=payload_hosts, headers=headers)
        hosts_data = res_hosts.json().get('result', [])
        metrics_count = 0
        
        for host in hosts_data:
            hostid = host['hostid']
            interfaces = host.get('interfaces', [])
            if not interfaces: continue
            
            inventory = host.get('inventory')
            os_info = 'N/A'
            if inventory:
                os_info = inventory.get('os') or inventory.get('os_full') or inventory.get('software') or 'N/A'
            
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
                        except (ValueError, KeyError):
                            pass
            
            if not found_any and host_status == "UNKNOWN":
                continue

            cur.execute("""
                INSERT INTO zabbix_current (ip_address, status, os_info, cpu_usage, ram_usage, disk_usage, uptime_sec)
                VALUES (%s, %s, %s, %s, %s, %s, %s) 
                ON CONFLICT (ip_address) 
                DO UPDATE SET status = EXCLUDED.status, os_info = EXCLUDED.os_info, cpu_usage = EXCLUDED.cpu_usage, 
                              ram_usage = EXCLUDED.ram_usage, disk_usage = EXCLUDED.disk_usage, 
                              uptime_sec = EXCLUDED.uptime_sec, last_update = CURRENT_TIMESTAMP
            """, (host_ip, host_status, os_info, metrics['cpu_usage'], metrics['ram_usage'], metrics['disk_usage'], metrics['uptime_sec']))

            if found_any and latest_clock > 0:
                metric_timestamp = datetime.fromtimestamp(latest_clock).strftime('%Y-%m-%d %H:%M:%S')
                cur.execute("""
                    INSERT INTO zabbix_history (ip_address, status, os_info, cpu_usage, ram_usage, disk_usage, uptime_sec, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (ip_address, timestamp) DO NOTHING
                """, (host_ip, host_status, os_info, metrics['cpu_usage'], metrics['ram_usage'], metrics['disk_usage'], metrics['uptime_sec'], metric_timestamp))
                
                if cur.rowcount > 0:
                    metrics_count += 1

        conn.commit()
        cur.close()
        log(f"Zabbix OK. Nova historie: {metrics_count} stroju.")

    except Exception as e:
        log(f"CHYBA Zabbix sberu: {e}")

def fetch_greenbone_data(conn):
    try:
        cur = conn.cursor()
        fetch_start_time = datetime.now()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect((GREENBONE_HOST, GREENBONE_PORT))

        auth_xml = f"<authenticate><credentials><username>{GREENBONE_USER}</username><password>{GREENBONE_PASS}</password></credentials></authenticate>"
        s.sendall(auth_xml.encode('utf-8'))
        
        auth_resp = b""
        while b"</authenticate_response>" not in auth_resp:
            chunk = s.recv(4096)
            if not chunk: break
            auth_resp += chunk
            
        if b'status="200"' not in auth_resp:
            log("Greenbone Auth Error: Zkontroluj heslo.")
            s.close()
            return
            
        req_xml = '<get_results filter="levels=chml rows=-1" details="1"/>'
        s.sendall(req_xml.encode('utf-8'))
        
        vuln_resp = b""
        while b"</get_results_response>" not in vuln_resp:
            chunk = s.recv(4096)
            if not chunk: break
            vuln_resp += chunk
            
        s.close()
        root = ET.fromstring(vuln_resp.decode('utf-8', errors='ignore'))
        vuln_count = 0
        
        for result in root.findall('.//result'):
            host = result.findtext('host', default='0.0.0.0')
            if host in ['127.0.0.1', 'any']: host = DOCKER_SERVER_IP
            
            threat = result.findtext('threat', default='Unknown')
            port = result.findtext('port', default='general/tcp')
            nvt = result.find('nvt')
            nvt_name = nvt.findtext('name', default='Unknown NVT') if nvt is not None else 'Unknown NVT'
            cvss = nvt.findtext('cvss_base', default='0.0') if nvt is not None else '0.0'
            
            # --- PŘIDÁNO: Vytěžení CVE ID ---
            cve_id = "N/A"
            if nvt is not None:
                refs = nvt.findall(".//ref[@type='cve']")
                if refs:
                    cve_id = ", ".join([r.get('id') for r in refs])

            try: cvss_val = float(cvss)
            except ValueError: cvss_val = 0.0

            if host == '0.0.0.0' or nvt_name == 'Unknown NVT':
                continue

            cur.execute("""
                INSERT INTO greenbone_vulns (ip_address, nvt_name, threat_level, cvss, port, cve)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (ip_address, nvt_name, port) 
                DO UPDATE SET threat_level = EXCLUDED.threat_level, cvss = EXCLUDED.cvss, cve = EXCLUDED.cve, timestamp = CURRENT_TIMESTAMP
            """, (host, nvt_name, threat, cvss_val, port, cve_id))
            vuln_count += 1
            
        cur.execute("DELETE FROM greenbone_vulns WHERE timestamp < %s", (fetch_start_time,))
        deleted_count = cur.rowcount
        conn.commit()
        cur.close()
        log(f"Greenbone OK. Zpracovano: {vuln_count} | Odstraneno: {deleted_count}")
        
    except socket.timeout:
        log("CHYBA Greenbone sberu: Casovy limit vyprsel.")
    except ET.ParseError:
        log("CHYBA Greenbone sberu: Spatne XML.")
    except Exception as e:
        log(f"CHYBA Greenbone sberu: {e}")

def cleanup_old_data(conn):
    try:
        cur = conn.cursor()
        cutoff_date = datetime.now() - timedelta(days=RETENTION_DAYS)
        cur.execute("DELETE FROM wazuh_alerts WHERE timestamp < %s", (cutoff_date,))
        wazuh_deleted = cur.rowcount
        cur.execute("DELETE FROM zabbix_history WHERE timestamp < %s", (cutoff_date,))
        zabbix_deleted = cur.rowcount
        conn.commit()
        cur.close()
        if wazuh_deleted > 0 or zabbix_deleted > 0:
            log(f"RETENCE OK. Smazano: Wazuh ({wazuh_deleted}), Zabbix ({zabbix_deleted})")
    except Exception as e:
        log(f"CHYBA Retence: {e}")

if __name__ == "__main__":
    log("=== SOC INTEGRATOR v5.9.0 STARTUJE ===")
    init_db()
    while True:
        db_conn = get_db_connection()
        if db_conn:
            fetch_wazuh_data(db_conn)
            fetch_zabbix_data(db_conn)
            fetch_greenbone_data(db_conn)
            cleanup_old_data(db_conn)
            db_conn.close()
        time.sleep(60)