from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import shutil
import zipfile
import os
import subprocess
import requests
import time
import csv
import io
import re
import html
import urllib.parse
import threading

# --- Config ---
SONAR_URL = os.getenv("SONAR_URL", "http://sonarqube-server:9000")
SONAR_USER = "admin"
SONAR_PASSWORD = os.getenv("SONAR_PASSWORD", "Sonar_Internal_Auth_123!") 
SCAN_DIR = "/app/scans"

# NEW: Global state to prevent interactions before SonarQube is ready
SYSTEM_READY = False

scan_statuses = {}
active_scans = {} # NEW: Tracks live subprocesses so we can kill them
templates = Jinja2Templates(directory="templates")

# --- Background Bootstrapper Logic ---
def setup_sonarqube():
    global SYSTEM_READY
    print("Waiting for SonarQube to initialize (this takes a minute on first boot)...")
    
    while True:
        try:
            res = requests.get(f"{SONAR_URL}/api/system/status", timeout=5)
            if res.status_code == 200 and res.json().get("status") == "UP":
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(5)

    print("SonarQube is UP. Checking authentication state...")
    test_auth = requests.get(f"{SONAR_URL}/api/users/current", auth=("admin", "admin"))
    
    if test_auth.status_code == 200:
        print("First boot detected. Auto-configuring secure internal password...")
        change_pwd = requests.post(
            f"{SONAR_URL}/api/users/change_password",
            data={"login": "admin", "previousPassword": "admin", "password": SONAR_PASSWORD},
            auth=("admin", "admin")
        )
        if change_pwd.status_code == 204:
            print("Password updated successfully! Portal is ready.")
            SYSTEM_READY = True
        else:
            print(f"Failed to change password: {change_pwd.text}")
            # Even if it fails, we unlock the portal so the user isn't permanently frozen
            SYSTEM_READY = True 
    else:
        print("Custom password already set. Portal is ready.")
        SYSTEM_READY = True

# --- FastAPI Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    threading.Thread(target=setup_sonarqube, daemon=True).start()
    yield

app = FastAPI(lifespan=lifespan)

# NEW: Endpoint for the frontend to check if it's safe to interact
@app.get("/system/status")
def system_status():
    return {"ready": SYSTEM_READY}


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/scan")
async def start_scan(background_tasks: BackgroundTasks, project_name: str = Form(...), file: UploadFile = File(...)):
    # Start at 10% for extraction
    project_name = project_name.strip().replace(" ", "-")
    scan_statuses[project_name] = {"status": "Extracting files...", "progress": 10}
    
    try:
        project_path = os.path.join(SCAN_DIR, project_name)
        os.makedirs(project_path, exist_ok=True)
        zip_path = os.path.join(project_path, file.filename)
        
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(project_path)
        os.remove(zip_path)
        
        background_tasks.add_task(run_sonar_scanner, project_name)
        return {"message": "Scan initiated", "project": project_name}
        
    except zipfile.BadZipFile:
        scan_statuses[project_name] = {"status": "Error: The uploaded file is not a valid ZIP archive.", "progress": -1}
        return {"error": "Bad Zip"}
    except Exception as e:
        scan_statuses[project_name] = {"status": f"Error during extraction: {str(e)}", "progress": -1}
        return {"error": str(e)}

# Make sure you added 'import re' at the top of your file!

def run_sonar_scanner(project_name: str):
    scan_statuses[project_name] = {"status": "Provisioning secure token...", "progress": 20}
    
    token_url = f"{SONAR_URL}/api/user_tokens/generate"
    token_params = {"name": f"token-{project_name}-{int(time.time())}"}
    token_resp = requests.post(token_url, params=token_params, auth=(SONAR_USER, SONAR_PASSWORD))
    
    if token_resp.status_code != 200:
        scan_statuses[project_name] = {"status": f"Error: Failed to generate token.", "progress": -1}
        return
        
    dynamic_token = token_resp.json().get("token")
    scan_statuses[project_name] = {"status": "Booting SonarScanner engine...", "progress": 25}
    
    # NEW: We added the --name flag so we can specifically target this container to kill it
    cmd = [
        "docker", "run", "--rm",
        "--name", f"scanner-{project_name}", 
        "--network", "sonar_net",
        "-v", "scan_data:/usr/src",
        "-w", f"/usr/src/{project_name}",
        "sonarsource/sonar-scanner-cli",
        f"-Dsonar.projectKey={project_name}",
        f"-Dsonar.host.url={SONAR_URL}",
        f"-Dsonar.token={dynamic_token}"
    ]
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    active_scans[project_name] = process # Track it
    
    current_progress = 25.0
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    
    for line in process.stdout:
        # Check if user aborted
        if scan_statuses.get(project_name, {}).get("status") == "Scan aborted by user.":
            break
            
        clean_line = ansi_escape.sub('', line).strip()
        
        if "Load global settings" in clean_line or "Load plugins index" in clean_line:
            current_progress = 30.0
            scan_statuses[project_name] = {"status": "Loading security rules and plugins...", "progress": 30}
        elif "Indexing files" in clean_line:
            current_progress = 35.0
            scan_statuses[project_name] = {"status": "Indexing project files...", "progress": 35}
        elif "Sensor" in clean_line and "INFO:" in clean_line:
            if current_progress < 75.0:
                current_progress += 2.0 
            if "(done)" not in clean_line:
                sensor_name = clean_line.split("Sensor ")[-1].split(" [")[0] if "Sensor " in clean_line else "Code Analyzer"
                scan_statuses[project_name] = {"status": f"Running analysis: {sensor_name}", "progress": int(current_progress)}
        elif "CPD Executor" in clean_line:
            current_progress = 75.0
            scan_statuses[project_name] = {"status": "Analyzing code duplication...", "progress": 75}
        elif "Analysis report generated" in clean_line:
            current_progress = 80.0
            scan_statuses[project_name] = {"status": "Packaging analysis report...", "progress": 80}
        elif "EXECUTION SUCCESS" in clean_line:
            current_progress = 85.0
            scan_statuses[project_name] = {"status": "Uploading report to SonarQube...", "progress": 85}

    process.wait()
    active_scans.pop(project_name, None) # Remove from tracker
    
    # If the process was killed, respect the aborted status
    if process.returncode != 0:
        if scan_statuses.get(project_name, {}).get("status") != "Scan aborted by user.":
            scan_statuses[project_name] = {"status": "Error: Scanner crashed. Check container logs.", "progress": -1}
        return

    revoke_url = f"{SONAR_URL}/api/user_tokens/revoke"
    requests.post(revoke_url, params={"name": token_params["name"]}, auth=(SONAR_USER, SONAR_PASSWORD))

    scan_statuses[project_name] = {"status": "Analysis complete. SonarQube is processing results...", "progress": 90}
    
    while True:
        if scan_statuses.get(project_name, {}).get("status") == "Scan aborted by user.":
            break
        try:
            ce_resp = requests.get(f"{SONAR_URL}/api/ce/component?component={project_name}", auth=(SONAR_USER, SONAR_PASSWORD))
            if ce_resp.status_code == 200:
                ce_data = ce_resp.json()
                queue = ce_data.get('queue', [])
                current = ce_data.get('current', {})
                if not queue and current.get('status') == 'SUCCESS':
                    scan_statuses[project_name] = {"status": "Complete", "progress": 100}
                    break
            time.sleep(3)
        except Exception:
            time.sleep(3)

@app.get("/status/{project_name}")
def get_status(project_name: str):
    # Default return if the project isn't tracked yet
    return scan_statuses.get(project_name, {"status": "Unknown", "progress": 0})

@app.get("/projects")
def get_projects():
    # Ask SonarQube for a list of all existing projects
    url = f"{SONAR_URL}/api/projects/search"
    try:
        resp = requests.get(url, auth=(SONAR_USER, SONAR_PASSWORD))
        if resp.status_code == 200:
            projects = resp.json().get('components', [])
            # Return a clean list of project names and keys to the frontend
            return {"projects": [{"name": p['name'], "key": p['key']} for p in projects]}
        return {"projects": []}
    except Exception as e:
        print(f"Error fetching projects: {e}")
        return {"projects": []}

def format_bytes(size):
    # Quick helper to make bytes readable
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

@app.post("/prepare_report/{project_name}")
def prepare_report(project_name: str, cols: str = None):
    if cols:
        selected_columns = cols.split(',')
    else:
        selected_columns = ['Vulnerability Name', 'Severity', 'Project Name', 'Context', 'Full Path', 'File', 'Line']

    all_findings = []
    
    # 1. Fetch Vulnerabilities
    page = 1
    while True:
        url = f"{SONAR_URL}/api/issues/search?componentKeys={project_name}&types=VULNERABILITY&additionalFields=rules&ps=500&p={page}"
        resp = requests.get(url, auth=(SONAR_USER, SONAR_PASSWORD))
        if resp.status_code == 200:
            data = resp.json()
            issues = data.get('issues', [])
            rules = {r['key']: r['name'] for r in data.get('rules', [])}
            for i in issues:
                all_findings.append({
                    'name': rules.get(i.get('rule'), i.get('rule')), 
                    'severity': i.get('severity', 'UNKNOWN'),
                    'project': i.get('project', project_name), 
                    'component': i.get('component', ''), 
                    'line': i.get('line', 'N/A'), 
                    'msg': i.get('message', '')
                })
            if len(issues) < 500: break
            page += 1
        else: break

    # 2. Fetch Hotspots
    page = 1
    while True:
        url = f"{SONAR_URL}/api/hotspots/search?projectKey={project_name}&ps=500&p={page}"
        resp = requests.get(url, auth=(SONAR_USER, SONAR_PASSWORD))
        if resp.status_code == 200:
            hotspots = resp.json().get('hotspots', [])
            for h in hotspots:
                all_findings.append({
                    'name': f"[HOTSPOT] {h.get('message', h.get('ruleKey'))}", 
                    'severity': h.get('vulnerabilityProbability', 'HOTSPOT').upper(),
                    'project': h.get('project', project_name), 
                    'component': h.get('component', ''), 
                    'line': h.get('line', 'N/A'), 
                    'msg': h.get('message', '')
                })
            if len(hotspots) < 500: break
            page += 1
        else: break

    # 3. Save the customized CSV to disk instead of streaming it
    report_dir = os.path.join(SCAN_DIR, project_name)
    os.makedirs(report_dir, exist_ok=True)
    file_path = os.path.join(report_dir, f"{project_name}_security_report.csv")

    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(selected_columns)
        
        for f_item in all_findings:
            full_comp = f_item['component']
            full_path = full_comp.split(':', 1)[-1] if ':' in full_comp else 'N/A'
            file_name = full_path.split('/')[-1] if full_path != 'N/A' else 'N/A'
            line_num = f_item['line']
            context_text = f_item['msg']
            
            if line_num != 'N/A' and full_comp:
                try:
                    start_line = max(1, int(line_num) - 1)
                    end_line = int(line_num) + 1
                except ValueError:
                    start_line, end_line = line_num, line_num

                encoded_comp = urllib.parse.quote(full_comp)
                lines_url = f"{SONAR_URL}/api/sources/lines?key={encoded_comp}&from={start_line}&to={end_line}"
                lines_resp = requests.get(lines_url, auth=(SONAR_USER, SONAR_PASSWORD))
                
                if lines_resp.status_code == 200:
                    sources = lines_resp.json().get('sources', [])
                    if sources:
                        raw_html = " ".join([s.get('code', '') for s in sources])
                        clean_code = html.unescape(re.sub(r'<[^>]+>', '', raw_html)).strip()
                        context_text = clean_code if clean_code else f"[Blank Line] {f_item['msg']}"
            
            row_data = {
                'Vulnerability Name': f_item['name'],
                'Severity': f_item['severity'],
                'Project Name': f_item['project'],
                'Context': context_text,
                'Full Path': full_path,
                'File': file_name,
                'Line': line_num
            }
            writer.writerow([row_data.get(col, '') for col in selected_columns])

    # 4. Calculate size and tell frontend it's ready
    file_size = os.path.getsize(file_path)
    return {"status": "ready", "size": format_bytes(file_size)}

@app.get("/download_report/{project_name}")
def download_report(project_name: str):
    # This serves the static file. FastAPI automatically injects the Content-Length size header!
    file_path = os.path.join(SCAN_DIR, project_name, f"{project_name}_security_report.csv")
    if not os.path.exists(file_path):
        return {"error": "Report not found"}
    return FileResponse(path=file_path, filename=f"{project_name}_security_report.csv", media_type='text/csv')

@app.post("/scan/abort/{project_name}")
def abort_scan(project_name: str):
    scan_statuses[project_name] = {"status": "Scan aborted by user.", "progress": -1}
    
    # Force stop the specific docker container if it's running
    subprocess.run(["docker", "stop", f"scanner-{project_name}"], capture_output=True)
    
    if project_name in active_scans:
        try:
            active_scans[project_name].terminate()
        except Exception:
            pass
        active_scans.pop(project_name, None)
        
    # Nuke the extracted files to save disk space
    project_path = os.path.join(SCAN_DIR, project_name)
    if os.path.exists(project_path):
        shutil.rmtree(project_path, ignore_errors=True)
        
    return {"message": "Aborted"}

@app.delete("/projects/{project_name}")
def delete_project(project_name: str):
    # Wipe from SonarQube Database
    resp = requests.post(f"{SONAR_URL}/api/projects/delete", params={"project": project_name}, auth=(SONAR_USER, SONAR_PASSWORD))
    
    # Wipe leftover files from volume
    project_path = os.path.join(SCAN_DIR, project_name)
    if os.path.exists(project_path):
        shutil.rmtree(project_path, ignore_errors=True)
        
    return {"success": resp.status_code in [200, 204]}