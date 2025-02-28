# LangGraph-Based-Agentic-Cybersecurity-Workflow
## Sytem Architecture
The __Cybersecurity Pipeline__ is an agentic workflow designed to automate penetration testing tasks using LangGraph and LangChain. It breaks down high-level security instructions into actionable steps, executes them sequentially, and dynamically updates the task list based on intermediate results. The system enforces scope constraints to ensure scans and analyses stay within user-defined boundaries.

### Key Components
1. #### LangGraph Workflow:
  - The core of the system is built using LangGraph, a framework for creating stateful, agentic workflows.
  - The workflow consists of two main nodes:
    - __Task Breakdown:__ Breaks down high-level instructions into actionable tasks.

    - __Task Execution:__ Executes tasks, handles failures, and updates the task list dynamically.
    
2.  #### LangChain Integration:
   - LangChain is used to interact with the Groq API (LLM) for generating commands, identifying dependencies, and prioritizing tasks.
   - The LLM (e.g., llama-3.3-70b-versatile) is responsible for:

      - Breaking down tasks.
      
      - Generating execution commands.
      
      - Parsing outputs and generating new tasks.

3. #### Security Tools Integration:
    - The system integrates with popular security tools like:
      - __nmap:__ For network mapping and port scanning.
      - __gobuster:__ For directory brute-forcing.
      - __ffuf:__ For web fuzzing.
      - __sqlmap:__ For SQL injection testing.
    - These tools are executed via subprocess calls, and their outputs are parsed to generate new tasks.
      
4. #### Scope Enforcement:
    - The system enforces a user-defined scope to ensure scans and analyses stay within allowed boundaries.
    - The scope can include:
      - Specific domains (e.g., google.com).
      - Wildcard domains (e.g., *.example.com).
      - IP addresses or ranges (e.g., 192.168.1.0/24).
        
5. #### State Management:
    - The system maintains a state object (SecurityState) that tracks:
      - The input instruction.
      - The task list (a deque of tasks)
      - Executed tasks (with results).
      - The defined scope.
      - Counters for retries, generations, and recursion.

6. #### Streamlit Frontend:
    - The system provides a Streamlit-based web interface for:
      - Defining the scan scope.
      - Entering high-level security instructions.
      - Viewing task execution results and final reports.

## Agent Roles and Responsibilities

### 1. Task Breakdown Agent
 - __Responsibility:__ Breaks down high-level security instructions into actionable tasks.
 - __Input:__ High-level instruction (e.g., "Scan google.com for open ports and discover directories").
 - __Output:__ Ordered list of tasks (e.g., "Run nmap scan on google.com", "Run gobuster scan on discovered subdomains").

### 2. Command Generation Agent
  - __Responsibility:__ Generates terminal commands for executing tasks.
  - __Input:__ Task (e.g., "Run nmap scan on google.com").
  - __Output:__ Terminal command (e.g., nmap -p 80, 443 google.com).

### 3. Dependency Checker
  - __Responsibility:__ Identifies tools or libraries required to execute a command.
  - __Input:__ Terminal command.
  - __Output:__ List of dependencies (e.g., nmap, gobuster).

### 4. Task Execution Agent
  - __Responsibility:__ Executes tasks, handles failures, and retries with alternative configurations.
  - __Input:__ Terminal command.
  - __Output:__ Execution result (success, failure, or error).

### 5. Output Parser
 - __Responsibility:__ Parses the output of executed commands and generates new tasks.
 - __Input:__ Command output (e.g., "Discovered open ports: 80, 443").
 - __Output:__ New tasks (e.g., "Scan port 80 for vulnerabilities").

### 6. Scope Enforcer
  - __Responsibility:__ Ensures all tasks operate within the defined scope.
  - __Input:__ Target (e.g., google.com).
  - __Output:__ Boolean (True if target is in scope, False otherwise).

## Scope Enforcement Strategy

The system enforces scope constraints to prevent scans and analyses from operating outside user-defined boundaries. The scope enforcement strategy includes:

1. ### Scope Definition:
  - Users define the scope at the start of each session using the Streamlit frontend.
  - The scope can include:
    - Specific domains (e.g., google.com).
    - Wildcard domains (e.g., *.example.com).
    - IP addresses or ranges (e.g., 192.168.1.0/24).

2. ### Target Validation:
  - Before executing a command, the system extracts the target (domain, IP, or URL) and checks if it is within the defined scope.
  - Targets are validated against:
    - Wildcard domains (e.g., test.example.com matches *.example.com).
    - IP ranges (e.g., 192.168.1.1 matches 192.168.1.0/24).

3. ### Out-of-Scope Handling:
  - If a target is out of scope, the system logs the failure and skips the task.
  - The user is notified of out-of-scope attempts via the Streamlit interface.

## Replication & Running Instructions

### Environment Setup

1. #### Python Version:
  - Use Python 3.11.

2. #### Virtual Environment:
  - Create a virtual environment:
    ```bash
    python -m venv venv
  - Activate the virtual environment:
    - __macOS/Linux__:
      ```bash
      source venv/bin/activate
    - __Windows:__
      ```bash
      .\venv\Scripts\activate
3. #### Dependency Management:
   - Install dependencies using requirements.txt:
     ```bash
     pip install -r requirements.txt
     
### Installation Instructions
1. #### System-Level Dependencies:
  - Install the following tools:
    - __nmap:__
      ```bash
      sudo apt install nmap  # On Ubuntu/Debian
      brew install nmap     # On macOS 
    - __gobuster__:
      ```bash
      sudo apt install gobuster  # On Ubuntu/Debian
      brew install gobuster      # On macOS
    - __ffuf:__
      ```bash
      sudo apt install ffuf  # On Ubuntu/Debian
      brew install ffuf      # On macOS
    - __sqlmap:__
      ```bash
      sudo apt install sqlmap  # On Ubuntu/Debian
      brew install sqlmap      # On macOS
2. #### Python Dependencies:
  - Install Python dependencies:
    ```bash
    pip install -r requirements.txt

### Configuration:
  1. #### Environment Variables:
  - Modify your Groq API Key in the pipeline.py or Create a .env file and add your Groq API Key which can be called in the pipeline.py:
     ```bash
     GROQ_API_KEY = your_groq_api_key
  2. #### Define Scope:
  - Use the Streamlit frontend to define the scan scope (e.g., google.com, *.example.com, 192.168.1.0/24).

### Running the Application:

1. #### Start the Streamlit App:
    ```bash
    streamlit run pipeline.py

2. #### Define Scope:
   - Enter the scan scope in the Streamlit interface (e.g., google.com, *.example.com, 192.168.1.0/24).
     
3. #### Enter Security Instructions:
  - Provide a high-level security instruction (e.g., "Scan google.com for open ports and discover directories").

4. #### Monitor Execution:
    - View task execution results, logs, and final reports in the Streamlit interface.

### Testing & Verification

1. #### Expected Outputs:
   - Successful task execution:
      ```bash
      Success: <command output>
   - Failed task execution:
      ```bash
      Failed: <error message>

2. #### Audit Logs:
  - Check the audit_log.txt file for detailed execution logs.

3. #### Unit Tests Written Using Pytest:

  - The unit tests for the cybersecurity pipeline are written using the pytest framework. These tests ensure that the various components of the pipeline function as expected.

  - __Install Pytest:__
      ```bash
      pip install pytest

  - __Run the Tests:__
      ```bash
      pytest test_cybersecurity_pipeline.py -v


     

