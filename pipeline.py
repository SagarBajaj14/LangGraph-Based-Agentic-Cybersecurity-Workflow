import os
import re
import subprocess
import platform
import shutil
import streamlit as st
from groq import Groq
from langgraph.graph import StateGraph, END
from typing import Dict, List, Deque
from collections import deque
from ipaddress import ip_network, ip_address
import datetime
import shlex
import time
import psutil

os.environ["GROQ_API_KEY"] = "[YOUR-GROQ-API-KEY]"
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

class SecurityState(Dict):
    input_instruction: str
    task_list: Deque[str]
    executed_tasks: List[Dict[str, str]]
    scope: List[str]
    generation_count: int  
    global_retry_count: int
    recursion_count: int

def is_tool_installed(tool_name):
    if shutil.which(tool_name) is not None:
        return True

    if platform.system().lower() == "windows":
        try:
            result = subprocess.run(
                ["wsl", "which", tool_name],
                shell=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode == 0:
                return True
        except Exception as e:
            st.error(f"Error checking WSL for {tool_name}: {str(e)}")

    return False

def identify_dependencies(command: str) -> List[str]:
    prompt = f"""
    You are a cybersecurity automation assistant. Analyze the following command and identify ONLY the tools or libraries required to execute it:
    
    Command: {command}
    
    Provide only the name of the dependencies in the command separated by comma, without any explanation.
    Example: nmap, dirb, gobuster, ffuf, sqlmap
    """
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    response = chat_completion.choices[0].message.content
    dependencies = [dep.strip().lower() for dep in response.split(",") if dep.strip()]
    return dependencies

def is_target_in_scope(target: str, scope: List[str]) -> bool:
    for item in scope:
        if item.startswith("*."):
            domain = item[2:]
            if target.endswith(domain):
                return True
        elif "/" in item:
            try:
                if ip_address(target) in ip_network(item, strict=False):
                    return True
            except ValueError:
                continue
        elif item in target:
            return True
    return False

def extract_target_from_command(command: str) -> str:
    target_pattern = re.compile(
        r"(https?://[^\s/$.?#].[^\s]*|[\w.-]+\.[a-zA-Z]{2,}|[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})"
    )
    match = target_pattern.search(command)
    if match:
        return match.group(1)
    return None

def split_commands(command: str) -> List[str]:
    return [cmd.strip() for cmd in command.split("&&")]

def task_breakdown(state: SecurityState) -> SecurityState:
    instruction = state["input_instruction"]
    scope = state["scope"]
    prompt = f"""
    You are a cybersecurity expert. Break down the following security instruction into an ordered list of actionable penetration testing tasks within the given scope:
    
    Instruction: {instruction}
    Scope: {', '.join(scope)}
    
    Provide the output as a single line of comma-separated values:
    First actionable step, Second actionable step, Third actionable step, ...
    """
    
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    response = chat_completion.choices[0].message.content
    task_list = deque(task.strip() for task in response.split(",") if task.strip())
    state["task_list"] = task_list
    state["executed_tasks"] = []
    state["global_retry_count"] = 0  
    state["generation_count"] = 0  
    return state

def fetch_execution_command(task: str, scope: List[str]) -> str:
    prompt = f"""
    You are a cybersecurity automation assistant. Generate the short and concise terminal command needed to execute the following task within the given scope:
    
    Task: {task}
    Scope: {', '.join(scope)}
    
    Replace placeholders like <website_URL> with a valid target from the scope.
    Provide only the command, without any explanation.
    Supported tools: nmap, dirb, gobuster, ffuf, sqlmap.
    """
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    command = chat_completion.choices[0].message.content.strip()
    return command

def generate_alternative_query(task: str, scope: List[str]) -> str:
    prompt = f"""
    You are a cybersecurity automation assistant. The following task failed:
    
    Task: {task}
    Scope: {', '.join(scope)}
    
    Generate an alternative short and concise query or command to achieve the same goal.
    Provide only the command, without any explanation.
    """
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    alternative_command = chat_completion.choices[0].message.content.strip()
    return alternative_command

def parse_output_and_generate_tasks(output: str, scope: List[str]) -> List[str]:
    prompt = f"""
    You are a cybersecurity automation assistant. Analyze the following command output and generate a list of new tasks to perform based on the findings:
    
    Output: {output}
    Scope: {', '.join(scope)}
    
    Provide the output as a single line of comma-separated values:
    First new task, Second new task, Third new task, ...
    """
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    response = chat_completion.choices[0].message.content
    new_tasks = [task.strip() for task in response.split(",") if task.strip()]
    return new_tasks

def prioritize_tasks(task_list: Deque[str]) -> Deque[str]:
    prompt = f"""
    You are a cybersecurity automation assistant. Prioritize the following list of tasks based on their relevance and importance:
    
    Tasks: {', '.join(task_list)}
    
    Provide the output as a single line of comma-separated values, ordered by priority (most important first):
    First task, Second task, Third task, ...
    """
    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
    )
    response = chat_completion.choices[0].message.content
    prioritized_tasks = [task.strip() for task in response.split(",") if task.strip()]
    return deque(prioritized_tasks)

def run_command_with_timeout(cmd, timeout):
    try:
        process = subprocess.Popen(
            shlex.split(cmd),  
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        start_time = time.time()
        while process.poll() is None: 
            if time.time() - start_time > timeout:
                parent = psutil.Process(process.pid)
                for child in parent.children(recursive=True):
                    child.terminate()
                parent.terminate()
                raise subprocess.TimeoutExpired(cmd, timeout)

            time.sleep(0.1)

        stdout, stderr = process.communicate()
        return stdout, stderr, process.returncode

    except subprocess.TimeoutExpired:
        raise
    except Exception as e:
        raise RuntimeError(f"Error running command: {str(e)}")

def execute_task(state: dict, timeout: int = 10, max_retries: int = 3, max_generations: int = 5) -> dict:
    task_list = state.get("task_list", deque())
    executed_tasks = state.get("executed_tasks", [])
    scope = state.get("scope", [])
    generation_count = state.get("generation_count", 0)  
    global_retry_count = state.get("global_retry_count", 0)  
    recursion_count = state.get("recursion_count", 0)

    if recursion_count >= 50:
        st.write("Recursion limit reached. Stopping execution.")
        return state

    state["recursion_count"] = recursion_count + 1

    st.write("Original task list:", task_list)
    
    if task_list:
        task_list = prioritize_tasks(task_list)
        state["task_list"] = task_list

    st.write("Prioritized task list:", task_list)

    if not task_list:
        return state

    task = task_list.popleft()
    st.write(f"Executing: {task}")

    if "original_task" not in state:
        state["original_task"] = task
    original_task = state["original_task"]

    command = fetch_execution_command(task, scope).strip("`")
    st.write(f"Running command: `{command}`")

    dependencies = identify_dependencies(command)
    st.write(f"Dependencies: {dependencies}")

    for dep in dependencies:
        if not is_tool_installed(dep):
            error_message = f"Failed: Dependency {dep} is not installed."
            st.write(error_message)
            executed_tasks.append({"task": task, "result": error_message})
            state["executed_tasks"] = executed_tasks
            
            global_retry_count += 1
            state["global_retry_count"] = global_retry_count
            st.write("Global retry count", global_retry_count)

            if global_retry_count >= max_retries:
                st.write(f"Skipping task after {max_retries} total retries: {original_task}")
                return state
            else:
                alternative_task = generate_alternative_query(original_task, scope)
                alternative_task = alternative_task.strip("`")
                if alternative_task:
                    task_list.appendleft(alternative_task)
                    st.write(f"Retrying with alternative task ({global_retry_count}/{max_retries}): {alternative_task}")
                else:
                    st.write(f"No alternative task generated. Skipping task: {original_task}")
                return state

    commands = split_commands(command)

    for cmd in commands:
        target = extract_target_from_command(cmd)
        if not target:
            st.write(f"No valid target found in command: {cmd}")
            executed_tasks.append({"task": task, "result": "Failed: No valid target found in command"})
            global_retry_count += 1
            state["global_retry_count"] = global_retry_count
            continue

        if not is_target_in_scope(target, scope):
            st.write(f"Target {target} is out of scope! Aborting execution.")
            executed_tasks.append({"task": task, "result": f"Failed: Target {target} is out of scope"})
            global_retry_count += 1
            state["global_retry_count"] = global_retry_count
            continue

        try:
            st.write("Running Terminal Command")
            if platform.system().lower() == "windows":
                if any(tool in cmd for tool in ["dirb", "nikto", "gobuster", "ffuf", "sqlmap"]):
                    cmd = f"wsl bash -c {shlex.quote(cmd)}"  
                elif "nmap" in cmd and shutil.which("nmap"):
                    pass
                else:
                    cmd = f"wsl bash -c {shlex.quote(cmd)}"

            stdout, stderr, returncode = run_command_with_timeout(cmd, timeout)

            if returncode == 0:
                executed_tasks.append({"task": task, "result": f"Success: {stdout}"})
                st.success(f"Success: {stdout}")

                if generation_count < max_generations:
                    new_tasks = parse_output_and_generate_tasks(stdout, scope)
                    if new_tasks:
                        st.write("Generated new tasks based on output:")
                        for new_task in new_tasks:
                            st.write(f"- {new_task}")

                        prioritized_new_tasks = prioritize_tasks(deque(new_tasks))
                        most_important_task = prioritized_new_tasks[0]
                        task_list.append(most_important_task)
                        st.write(f"Adding the most important task: {most_important_task}")
                        generation_count += 1
                        state["generation_count"] = generation_count
                        st.write("Generation Count:", generation_count)
                    else:
                        st.write("No new tasks generated from the output.") 
                else:
                    st.write("Max generations reached. No new tasks will be generated.")
            else:
                error_message = f"Failed: {stderr}"
                st.error(error_message)
                executed_tasks.append({"task": task, "result": f"Failed: {stderr}"})
                global_retry_count += 1
                state["global_retry_count"] = global_retry_count
        
        except subprocess.TimeoutExpired:
            st.write(f"Task timeout expired: {task}")
            executed_tasks.append({"task": task, "result": "Failed: Timeout expired"})
            global_retry_count += 1
            state["global_retry_count"] = global_retry_count

        except Exception as e:
            error_message = f"Error: {str(e)}"
            st.write(error_message)
            executed_tasks.append({"task": task, "result": f"Error: {str(e)}"})
            global_retry_count += 1
            state["global_retry_count"] = global_retry_count

    state["executed_tasks"] = executed_tasks
    state["task_list"] = task_list
    return state

def generate_final_report(state: SecurityState):
    st.subheader("Cybersecurity Pipeline Final Report")

    st.write(f"**Scope:** {', '.join(state['scope'])}")

    st.subheader("Executed Tasks")
    for i, task in enumerate(state["executed_tasks"], start=1):
        result = task['result']
        if "Success" in result:
            status = "Success"
        elif "Failed" in result:
            status = "Failed"
        else:
            status = "Error"
        
        st.write(f"{i}. **Task:** {task['task']}")
        st.write(f"   **Status:** {status}")
        st.write(f"   **Result:** {result}")
        st.write("") 

    st.subheader("Summary")
    st.write(f"- **Total Tasks Executed:** {len(state['executed_tasks'])}")
    st.write(f"- **Tasks Succeeded:** {len([t for t in state['executed_tasks'] if 'Success' in t['result']])}")
    st.write(f"- **Tasks Failed:** {len([t for t in state['executed_tasks'] if 'Failed' in t['result']])}")
    st.write(f"- **Tasks Errored:** {len([t for t in state['executed_tasks'] if 'Error' in t['result']])}")

def log_audit_trail(state: SecurityState, filename: str = "audit_log.txt"):
    with open(filename, "w") as log_file:
        log_file.write("Cybersecurity Pipeline Audit Log \n\n")
        log_file.write(f"Scope: {', '.join(state['scope'])}\n\n")
        log_file.write("Task Execution Log\n")
        
        for task in state["executed_tasks"]:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_file.write(f"[{timestamp}] Task: {task['task']}\n")
            log_file.write(f"   Result: {task['result']}\n\n")

graph = StateGraph(SecurityState)
graph.add_node("breakdown", task_breakdown)
graph.add_node("execute", execute_task)

graph.set_entry_point("breakdown")
graph.add_edge("breakdown", "execute")
graph.add_conditional_edges(
    "execute",
    lambda state: "execute" if state["task_list"] and state["recursion_count"] < 50 else END,
) 

workflow = graph.compile()

st.title("Cybersecurity Pipeline")

with st.form("scope_form"):
    st.write("Define your scan scope:")
    scope_input = st.text_input("Enter scope (comma-separated domains, wildcards, or IPs):", placeholder="e.g., google.com, *.example.com, 192.168.1.0/24")
    submitted = st.form_submit_button("Set Scope")

if submitted and scope_input:
    scope = [item.strip() for item in scope_input.split(",")]
    st.session_state["scope"] = scope
    st.success(f"Scope set: {', '.join(scope)}")

if "scope" in st.session_state:
    with st.form("task_form"):
        st.write("Enter your high-level security instructions:")
        instruction = st.text_input("Example: 'Scan google.com for open ports and discover directories'")
        submitted = st.form_submit_button("Submit")

    if submitted and instruction:
        st.write(f"Received instruction: {instruction}")
        input_data = {"input_instruction": instruction, "scope": st.session_state["scope"]}
        
        output = workflow.invoke(input_data)

        st.subheader("Ordered Task List")
        for i, task in enumerate(output["executed_tasks"], start=1):
            st.write(f"**{i}. {task['task']}**")

        st.subheader("Execution Results")
        for task in output["executed_tasks"]:
            if "Success" in task["result"]:
                st.success(f"{task['result']}")
            elif "Failed" in task["result"]:
                st.warning(f"{task['result']}")
            else:
                st.error(f"{task['result']}")

        st.subheader("Final Report")
        generate_final_report(output)

        log_audit_trail(output, "audit_log.txt")
        st.success("Audit log saved to 'audit_log.txt'")
else:
    st.warning("Please define your scope first.")