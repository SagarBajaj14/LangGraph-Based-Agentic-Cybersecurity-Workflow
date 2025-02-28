import pytest
from typing import Dict, List, Deque
from collections import deque
from unittest.mock import patch
import subprocess
from pipeline import (
    SecurityState,
    is_tool_installed,
    identify_dependencies,
    is_target_in_scope,
    extract_target_from_command,
    split_commands,
    task_breakdown,
    fetch_execution_command,
    generate_alternative_query,
    parse_output_and_generate_tasks,
    prioritize_tasks,
    run_command_with_timeout,
    execute_task,
)

class MockGroqResponse:
    def __init__(self, content):
        self.choices = [self]  
        self.message = self    
        self.content = content 

@pytest.fixture
def sample_state():
    return SecurityState(
        input_instruction="Scan google.com for open ports",
        task_list=deque(),
        executed_tasks=[],
        scope=["google.com", "*.example.com", "192.168.1.0/24"],
        generation_count=0,
        global_retry_count=0,
        recursion_count=0,
    )

@pytest.fixture
def mock_groq_client(monkeypatch):
    def mock_chat_completions_create(*args, **kwargs):
        return MockGroqResponse("nmap, gobuster")

    monkeypatch.setattr("new.client.chat.completions.create", mock_chat_completions_create)

def test_task_execution_flow(sample_state, mock_groq_client):
    state = task_breakdown(sample_state)
    assert len(state["task_list"]) > 0, "Task list should not be empty after breakdown."

    task = state["task_list"][0]
    command = fetch_execution_command(task, state["scope"])
    assert "nmap" in command or "gobuster" in command, "Command should include nmap or gobuster."

    dependencies = identify_dependencies(command)
    assert "nmap" in dependencies or "gobuster" in dependencies, "Dependencies should include nmap or gobuster."

    state = execute_task(state)
    assert len(state["executed_tasks"]) > 0, "At least one task should be executed."

def test_scope_enforcement(sample_state):
    assert is_target_in_scope("google.com", sample_state["scope"]), "google.com should be in scope."
    assert is_target_in_scope("test.example.com", sample_state["scope"]), "test.example.com should be in scope (wildcard)."
    assert is_target_in_scope("192.168.1.1", sample_state["scope"]), "192.168.1.1 should be in scope (IP range)."

    assert not is_target_in_scope("yahoo.com", sample_state["scope"]), "yahoo.com should be out of scope."
    assert not is_target_in_scope("192.168.2.1", sample_state["scope"]), "192.168.2.1 should be out of scope."

def test_failure_detection_and_retry(sample_state, mock_groq_client):
    sample_state["task_list"] = deque(["Invalid Task"])
    sample_state = execute_task(sample_state)
    assert "Failed" in sample_state["executed_tasks"][0]["result"], "Task should fail due to invalid command."

    assert sample_state["global_retry_count"] == 1, "Global retry count should increment after failure."
    assert len(sample_state["task_list"]) > 0, "Alternative task should be added to the task list."

def test_command_timeout(sample_state, mock_groq_client):
    def mock_fetch_execution_command(task, scope):
        return "nmap google.com"

    def mock_run_command_with_timeout(cmd, timeout):
        raise subprocess.TimeoutExpired(cmd, timeout)

    with patch(
        "pipeline.fetch_execution_command", 
        side_effect=mock_fetch_execution_command
    ), patch(
        "pipeline.run_command_with_timeout", 
        side_effect=mock_run_command_with_timeout
    ):
        sample_state["task_list"] = deque(["Scan google.com for open ports"])
        sample_state = execute_task(sample_state)

        assert "Failed: Timeout expired" in sample_state["executed_tasks"][0]["result"]

def test_dynamic_task_generation(sample_state, mock_groq_client):
    output = "Discovered open ports: 80, 443"
    new_tasks = parse_output_and_generate_tasks(output, sample_state["scope"])
    assert len(new_tasks) > 0, "New tasks should be generated based on output."

    prioritized_tasks = prioritize_tasks(new_tasks)
    assert len(prioritized_tasks) > 0, "Tasks should be prioritized."

def test_dependency_check():
    assert is_tool_installed("python"), "Python should be installed."
    assert not is_tool_installed("nonexistent_tool"), "Non-existent tool should not be installed."

def test_target_extraction():
    command = "nmap google.com"
    target = extract_target_from_command(command)
    assert target == "google.com", "Target should be extracted from command."

def test_command_splitting():
    commands = split_commands("nmap google.com && gobuster dir -u google.com")
    assert len(commands) == 2, "Command should be split into two parts."
    assert "nmap google.com" in commands, "First command should be nmap."
    assert "gobuster dir -u google.com" in commands, "Second command should be gobuster."