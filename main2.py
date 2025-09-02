import os
os.environ.setdefault("CREWAI_TELEMETRY_DISABLED", "1")
# Some stacks also honor these OTEL vars; clearing them prevents exports
os.environ.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", "")
os.environ.setdefault("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process
import logging
from datetime import datetime
import json, time

from tools import (
    nmap_scan, metasploit_exploit,vulnerability_scan, gemini_consultation, gobuster_scan, dirb_scan, hydra_brute_force, 
    web_vulnerability_scan, dvwa_authenticated_scan,cve_lookup, 
    execute_custom_script, generate_markdown_report, add_to_long_term_memory, 
    retrieve_from_long_term_memory, record_exploit_outcome, get_exploit_scores_tool,
    generate_html_report, calculate_cvss_score, visualize_attack_path,
    meterpreter_command_tool, shell_command_tool, add_scheduled_task_tool,
    add_cron_job_tool, ids_detection_tool, siem_integration_tool
)
load_dotenv()
from database import init_db, get_all_findings

log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"pentest_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.info("Automated Penetration Test Log Started.")


from litellm import completion as litellm_completion
from litellm.exceptions import RateLimitError

logger = logging.getLogger(__name__)
LITELLM_MODEL = os.getenv('LITELLM_MODEL', 'gemini/gemini-2.5-flash')

import os, time, json, logging
from litellm import completion as litellm_completion
from litellm.exceptions import RateLimitError, APIConnectionError

logger = logging.getLogger(__name__)

class LiteLLMAdapter:
    def __init__(self, model: str, temperature: float = 0.3, max_retries: int = 5):
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries


    def _trim_messages(self, messages, max_chars=8000):
        s = json.dumps(messages)
        if len(s) <= max_chars:
            return messages
        # keep system + last few exchanges
        system = [m for m in messages if m.get("role") == "system"][:1]
        rest = [m for m in messages if m.get("role") != "system"][-6:]
        return system + rest

    def call(self, prompt: str = None, messages: list | None = None, **kwargs) -> str:
        if messages is None:
            messages = [{"role": "user", "content": prompt or ""}]

        # Map GOOGLE_API_KEY -> GEMINI_API_KEY if needed
        provider = (self.model.split("/", 1)[0] if "/" in self.model else "openai").lower()
        if provider == "gemini" and not os.getenv("GEMINI_API_KEY") and os.getenv("GOOGLE_API_KEY"):
            os.environ["GEMINI_API_KEY"] = os.getenv("GOOGLE_API_KEY")

        params = dict(
            model=self.model,
            messages=self._trim_messages(messages),
            temperature=self.temperature,
            max_output_tokens=1536,
            timeout=60,          # important: client timeout
            num_retries=0,       # we do our own backoff for more control
        )
        params.update({k: v for k, v in kwargs.items() if v is not None})

        delay = 3
        for attempt in range(1, self.max_retries + 1):
            try:
                r = litellm_completion(**params)
                choices = r.get("choices", [])
                if not choices:
                    raise RuntimeError("Empty response choices from provider.")
                txt = choices[0].get("message", {}).get("content") or choices[0].get("text", "")
                if not txt:
                    raise RuntimeError("Provider returned no content.")
                return txt

            except (APIConnectionError, RateLimitError) as e:
                logger.warning(f"[LLM] transient error {type(e).__name__} (attempt {attempt}/{self.max_retries}) → backoff {delay}s")
                if attempt == self.max_retries:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 30)

            except Exception as e:
                logger.exception(f"[LLM] non-retryable error on attempt {attempt}: {e}")
                if attempt == self.max_retries:
                    return f"[LLM Error] {e}"
                time.sleep(delay)
                delay = min(delay * 2, 30)
# Pass this 'llm' into your CrewAI agents
llm = LiteLLMAdapter(model=LITELLM_MODEL, temperature=0.3)


infrastructure_agent = Agent(
    role='Infrastructure Assessment Specialist',
    goal='Conduct deep assessment of network infrastructure services including SSH, FTP, '
         'database services, and other network daemons. Identify misconfigurations, weak '
         'credentials, and service-specific vulnerabilities. Consult Google Gemini AI for infrastructure testing strategies and give final answer.',
    backstory=(
        "You are a network infrastructure expert with deep knowledge of service protocols, "
        "common misconfigurations, and infrastructure-level vulnerabilities. You specialize "
        "in assessing the core network services that form the backbone of organizational IT infrastructure."
    ),
    tools=[hydra_brute_force, nmap_scan, vulnerability_scan, gemini_consultation,
           retrieve_from_long_term_memory],  # Added list function
    verbose=False,
    allow_delegation=False,
    llm=llm
)


vuln_analysis_agent = Agent(
    role='Vulnerability Analyst',
    goal='Analyze reconnaissance data to identify specific vulnerabilities, misconfigurations, '
         'and suggest attack vectors. Provide CVSS scores for critical vulnerabilities.'
         'Research services and applications for known exploits and weaknesses. '
         'Consult Google Gemini AI for vulnerability assessment strategies and give final answer.',
    backstory=(
        "You are a sharp-witted vulnerability assessment expert. You take raw scan data and "
        "correlate it with known CVEs, misconfigurations, and common weaknesses. Your insights "
        "guide the exploitation phase, and you provide quantitative risk assessments."
    ),
    tools=[cve_lookup, vulnerability_scan, calculate_cvss_score, gemini_consultation,
           retrieve_from_long_term_memory],
    verbose=False,
    allow_delegation=False,
    ll=llm
    
)


# Agent 3: Exploitation Expert
exploitation_agent = Agent(
    role='Exploitation Expert',
    goal='Safely and ethically attempt to exploit identified vulnerabilities to gain access or '
         'demonstrate impact. Prioritize non-destructive methods and learn from past attempts. '
         'If successful, establish persistence and enumerate basic system info.'
         'Consult DeepSeek AI for exploitation strategies and give final answer only in English.',
    backstory=(
        "You are a highly skilled ethical hacker, specializing in leveraging known exploits and "
        "crafting custom payloads. You are precise, stealthy, and focused on demonstrating "
        "real-world impact while adhering to ethical guidelines. You learn from every attempt."
    ),
    tools=[metasploit_exploit, hydra_brute_force, execute_custom_script, 
           meterpreter_command_tool, shell_command_tool, add_scheduled_task_tool, 
           add_cron_job_tool, record_exploit_outcome, get_exploit_scores_tool,
           gemini_consultation, add_to_long_term_memory, retrieve_from_long_term_memory],
    verbose=False,
    allow_delegation=False,
    llm=llm
)


# Agent 4: Post-Exploitation Specialist
post_exploit_agent = Agent(
    role='Post-Exploitation Specialist',
    goal='After initial compromise, enumerate users, dump hashes, find sensitive files, '
         'and identify lateral movement opportunities. Establish persistence if possible.',
    backstory=(
        "You are a stealthy and methodical post-exploitation expert. Once a foothold is gained, "
        "you meticulously explore the compromised system to gather valuable intelligence, "
        "escalate privileges, and secure persistence mechanisms."
    ),
    tools=[meterpreter_command_tool, shell_command_tool, add_scheduled_task_tool, add_cron_job_tool,
           add_to_long_term_memory, retrieve_from_long_term_memory],
    verbose=False,
    allow_delegation=False,
    llm=llm
)


reporting_agent = Agent(
    role='Penetration Test Reporter',
    goal='Compile all findings, actions, and impacts into a comprehensive, professional, and actionable penetration test report. '
         'Include executive summary, detailed findings, exploitation proof, remediation recommendations, and attack path visualization.',
    backstory=(
        "You are a meticulous technical writer and cybersecurity expert. You translate complex "
        "technical findings into clear, concise, and professional reports that provide actionable "
        "recommendations for remediation. Your reports are the final, high-quality deliverable."
    ),
    tools=[generate_markdown_report, generate_html_report, visualize_attack_path, siem_integration_tool],
    verbose=False,
    allow_delegation=False,
    llm=llm
)


INFRASTRUCTURE_TARGET = os.getenv("INFRASTRUCTURE_TARGET", "192.168.56.20")


infrastructure_task = Task(
    description=(
        f"Conduct deep infrastructure assessment on target {INFRASTRUCTURE_TARGET}. "
        "Perform comprehensive Nmap scanning to identify all services. "
        "For discovered services (SSH, FTP, databases, etc.), use appropriate assessment tools. "
        "Attempt brute force attacks using 'hydra_brute_force' where appropriate. "
        "Consult Google Gemini AI for infrastructure testing strategies and give final answer only in English. "
        "Document all findings, especially weak credentials and misconfigurations."
    ),
    expected_output=(
        "A structured report detailing infrastructure assessment findings, including "
        "service discoveries, configuration issues, weak credentials found, and potential attack vectors. "
        "Include recommendations for securing the infrastructure."
    ),
    agent=infrastructure_agent,
    output_file='reports/infrastructure_assessment_report.md'
)

# Task 3: Vulnerability Analysis
vuln_analysis_task = Task(
    description=(
        f"Analyze the reconnaissance data for {INFRASTRUCTURE_TARGET} to identify specific vulnerabilities. "
        "Use 'cve_lookup' for discovered services and versions. "
        "For web vulnerabilities, use 'web_vulnerability_scan' for deeper analysis if needed. "
        "For each identified vulnerability, use 'calculate_cvss_score' if a CVSS vector is available or can be inferred. "
        "Suggest potential exploitation paths, including specific Metasploit modules or custom scripts, "
        "and prioritize based on severity and exploit scores from 'get_exploit_scores_tool'."
        "Store critical vulnerabilities and their CVSS scores in long-term memory."
    ),
    expected_output=(
        "A structured markdown report listing all identified vulnerabilities, their severity (CVSS score), "
        "associated CVEs, and specific recommendations for how they might be exploited (Metasploit modules, custom scripts). "
        "If no direct exploits are apparent, suggest areas for deeper manual investigation. "
        "Confirm that critical vulnerabilities have been added to long-term memory."
    ),
    agent=vuln_analysis_agent,
    context=[infrastructure_task],
    output_file='reports/vuln_analysis_report.md'
)


# Task 3: Exploitation
exploitation_task = Task(
    description=(
        f"Based on the vulnerability analysis for {INFRASTRUCTURE_TARGET}, attempt to exploit the most critical "
        "vulnerability to gain access or demonstrate impact. "
        "Before attempting, use 'get_exploit_scores_tool' to check past success rates for suggested exploits. "
        "Use 'metasploit_exploit' or 'execute_custom_script'. "
        "Upon successful exploitation, immediately delegate to the Post-Exploitation Specialist to enumerate basic system info and establish persistence. "
        "Record the outcome of the exploit using 'record_exploit_outcome' for future learning. "
        "Document the steps taken, the exploit used, and the outcome (e.g., shell access, data exfiltration proof)."
    ),
    expected_output=(
        "A markdown report detailing the successful exploitation, including the exploit module/script used, "
        "payload, target details, and clear proof of impact (e.g., screenshot of shell, extracted dummy data). "
        "If exploitation fails, explain the reasons and suggest next steps. "
        "Confirm outcome recorded and delegation to Post-Exploitation Agent if successful."
    ),
    agent=exploitation_agent,
    context=[vuln_analysis_task],
    output_file='reports/exploitation_report.md'
)


# Task 4: Post-Exploitation 
post_exploitation_task = Task(
    description=(
        f"You are now on a compromised system ({INFRASTRUCTURE_TARGET}). "
        "Your goal is to enumerate users, dump hashes, find sensitive files (e.g., /etc/passwd, config files), "
        "and identify lateral movement opportunities. Attempt to establish persistence using 'add_scheduled_task_tool' "
        "or 'add_cron_job_tool' based on the target OS. "
        "Use 'meterpreter_command_tool' or 'shell_command_tool' as appropriate. "
        "Store all findings in long-term memory."
    ),
    expected_output=(
        "A markdown report detailing post-exploitation activities, including enumerated users, "
        "any dumped hashes (simulated), sensitive files found, and confirmation of persistence established. "
        "Confirm all findings stored in long-term memory."
    ),
    agent=post_exploit_agent,
    context=[exploitation_task], 
    output_file='reports/post_exploitation_report.md'
)


# Task 4: Final Report Generation
final_report_task = Task(
    description=(
        f"Retrieve ALL findings from the database for the penetration test on {INFRASTRUCTURE_TARGET}"
        "using the 'get_all_findings' tool. "
        "Compile a comprehensive, professional penetration test report. "
        "The report MUST include: "
        "1. Executive Summary (High-level findings, overall risk, key recommendations).\n"
        "2. Scope (Target IP/URL, type of test).\n"
        "3. Reconnaissance Findings (Detailed Nmap results, discovered services, OS, IDS/IPS status).\n"
        "4. Vulnerability Analysis (Identified vulnerabilities, CVEs, CVSS scores, potential impact).\n"
        "5. Exploitation Details (If successful: exploit used, steps, proof of access/impact. If failed: reasons).\n"
        "6. Post-Exploitation Summary (Users enumerated, hashes/sensitive files found, persistence details).\n"
        "7. Remediation Recommendations (Actionable steps for each identified vulnerability).\n"
        "8. Attack Path Visualization (Generate using 'visualize_attack_path' tool and embed in report or provide link).\n"
        "Use 'generate_html_report' tool to create the final report. "
        "Also, use 'siem_integration_tool' to simulate sending a critical alert to a SIEM for each major finding."
    ),
    expected_output=(
        "The file path to the generated HTML penetration test report. "
        "Confirm that a SIEM alert has been simulated for critical findings."
    ),
    agent=reporting_agent,
    context=[infrastructure_task, vuln_analysis_task, exploitation_task, post_exploitation_task], 
    output_file='reports/final_report.html'
)


# --- 6. Orchestrating the Crew ---
pen_test_crew = Crew(
    agents=[infrastructure_agent, vuln_analysis_agent, exploitation_agent, post_exploit_agent, reporting_agent],
    tasks=[infrastructure_task, vuln_analysis_task, exploitation_task, post_exploitation_task, final_report_task],
    process=Process.sequential, 
    verbose=True 
)


# --- 7. Running the Project ---
if __name__ == "__main__":
    logger.info("## Starting the Automated Penetration Test Crew ##")
    logger.info("-------------------------------------------------")

    from database import init_db
    init_db()
    
   
    
    results = pen_test_crew.kickoff()

    logger.info("\n## Automated Penetration Test Completed! ##")
    logger.info("------------------------------------------")
    logger.info("Here is the final result of the Crew's work:")
    logger.info(results)

    
    report_path = os.path.join(os.getcwd(), 'reports', 'final_report.html')
    if os.path.exists(report_path):
        logger.info(f"\nCheck the generated HTML report file: {report_path}")
        
    else:
        logger.warning(f"Final report not found at {report_path}. Check logs for errors during report generation.")

        all_findings = get_all_findings()
        logger.info(f"\nTotal findings recorded in database: {len(all_findings)}")
