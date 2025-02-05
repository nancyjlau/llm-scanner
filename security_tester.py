#!/usr/bin/env python3
"""
security-tester.py – a demo vulnerability scanner using llm-powered analysis.
Uses OpenRouter + Claude for security testing with improved prompts and error handling.
Usage: python security_tester.py <path_to_codebase>
"""

import os
import sys
import ast
import io
import json
import requests
from typing import Dict, List, Any
from datetime import datetime

# --- LLM Integration ---
OPENROUTER_KEY = os.getenv("OPENROUTER_KEY")
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "anthropic/claude-3-sonnet"

class ModelError(Exception):
    pass

def call_llm(prompt: str, max_tokens: int = 500, temperature: float = 0.7, debug: bool = True) -> str:
    if not OPENROUTER_KEY:
        raise ValueError("OPENROUTER_KEY environment variable not set")

    if debug:
        print(f"\n[llm call] prompt:\n{prompt}\n")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "Security Testing Assistant"
    }

    data = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature
    }

    try:
        response = requests.post(OPENROUTER_ENDPOINT, headers=headers, json=data)
        response.raise_for_status()
        res_json = response.json()

        if "error" in res_json:
            error_msg = res_json.get("error", {}).get("message", "Unknown API error")
            raise ModelError(f"API error: {error_msg}")

        if "choices" not in res_json or not res_json["choices"]:
            raise ModelError(f"Invalid response format: {res_json}")

        content = res_json["choices"][0].get("message", {}).get("content")
        if not content:
            raise ModelError("Empty response from model")

        result = content

    except requests.exceptions.RequestException as e:
        result = f"API request failed: {str(e)}"
    except json.JSONDecodeError as e:
        result = f"Invalid JSON response: {str(e)}"
    except ModelError as e:
        result = f"Model error: {str(e)}"
    except Exception as e:
        result = f"Unexpected error: {str(e)}"

    if debug:
        print(f"[llm call] result:\n{result}\n")

    return result

class Indexer:
    def __init__(self, root_path: str):
        self.root_path = root_path
        self.index: Dict[str, List[Dict[str, Any]]] = {}

    def index_file(self, filepath: str) -> None:
        try:
            with open(filepath, "r") as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
            lines = source.splitlines()
            funcs = []

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    start = node.lineno - 1
                    end = node.end_lineno if hasattr(node, 'end_lineno') else node.lineno
                    snippet = "\n".join(lines[start:end])

                    func_info = {
                        "name": node.name,
                        "calls": [],
                        "snippet": snippet
                    }

                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                            func_info["calls"].append(sub.func.id)

                    funcs.append(func_info)

            self.index[filepath] = funcs

        except Exception as e:
            print(f"[indexer] error in {filepath}: {e}")

    def run(self) -> Dict[str, List[Dict[str, Any]]]:
        for root, _, files in os.walk(self.root_path):
            for file in files:
                if file.endswith(".py"):
                    self.index_file(os.path.join(root, file))
        return self.index

class SecurityAnalyzer:
    def __init__(self, code_index: Dict[str, List[Dict[str, Any]]]):
        self.code_index = code_index

    def analyze_function(self, func_info: Dict[str, Any]) -> str:
        prompt = f"""You are conducting a security analysis of Python code. Examine this function for security issues:

{func_info['snippet']}

Focus on:
1. Dangerous functions (eval, exec, etc.)
2. Input validation issues
3. Data exposure risks
4. Code injection vulnerabilities
5. Resource management

If no security issues are found, respond only with: SECURE
If issues are found, explain them clearly and concisely."""

        return call_llm(prompt, max_tokens=500)

    def generate_test_case(self, func_info: Dict[str, Any], analysis: str) -> str:
        prompt = f"""For this function that has security considerations:

{func_info['snippet']}

Analysis:
{analysis}

Create a Python test case that demonstrates the security concern. Include:
1. Example inputs that highlight the issue
2. Expected vs actual behavior
3. Why this represents a security risk

Keep the test case educational and non-malicious."""

        return call_llm(prompt, max_tokens=300)

    def suggest_improvements(self, func_info: Dict[str, Any], analysis: str) -> str:
        prompt = f"""For this function with security concerns:

{func_info['snippet']}

Issue identified:
{analysis}

Provide concrete recommendations to improve security:
1. Specific code changes needed
2. Alternative approaches
3. Best practices to follow
4. Additional safeguards to consider"""

        return call_llm(prompt, max_tokens=300)

    def run(self) -> List[Dict[str, Any]]:
        findings = []

        for filepath, funcs in self.code_index.items():
            for func in funcs:
                print(f"[*] Analyzing {func['name']} in {filepath}...")

                analysis = self.analyze_function(func)
                if analysis.strip() == "SECURE":
                    continue

                test_case = self.generate_test_case(func, analysis)
                improvements = self.suggest_improvements(func, analysis)

                findings.append({
                    "file": filepath,
                    "function": func["name"],
                    "analysis": analysis.strip(),
                    "test_case": test_case.strip(),
                    "improvements": improvements.strip(),
                    "code": func["snippet"]
                })

        return findings

class Reporter:
    def __init__(self, findings, total_files=0, total_functions=0):
        self.findings = findings
        self.total_files = total_files
        self.total_functions = total_functions
        self.total_issues = len(findings)
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_report(self) -> str:
        html = """
        <html>
        <head>
            <title>Security Analysis Report</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    margin: 40px;
                    background: #f5f5f5;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                h1 {
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }
                h2 {
                    color: #2980b9;
                    margin-top: 30px;
                }
                .overview {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 6px;
                    margin: 20px 0;
                }
                .finding {
                    margin-bottom: 30px;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    background: white;
                }
                .finding:hover {
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }
                .severity-high {
                    border-left: 4px solid #e74c3c;
                }
                .severity-medium {
                    border-left: 4px solid #f39c12;
                }
                .severity-low {
                    border-left: 4px solid #3498db;
                }
                pre {
                    background: #2c3e50;
                    color: #ecf0f1;
                    padding: 15px;
                    border-radius: 4px;
                    overflow-x: auto;
                }
                .stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }
                .stat-box {
                    background: white;
                    padding: 20px;
                    border-radius: 6px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }
                .recommendations {
                    background: #e8f4f8;
                    padding: 20px;
                    border-radius: 6px;
                    margin-top: 15px;
                }
                .test-case {
                    background: #fff8dc;
                    padding: 15px;
                    border-radius: 4px;
                    margin-top: 10px;
                }
                .timestamp {
                    color: #666;
                    font-size: 0.9em;
                    text-align: right;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
        <div class="container">
            <h1>🔐 Security Analysis Report</h1>
        """

        # Add Overview Section
        html += f"""
            <div class="overview">
                <h2>📊 Overview</h2>
                <div class="stats">
                    <div class="stat-box">
                        <h3>{self.total_files}</h3>
                        <p>Files Analyzed</p>
                    </div>
                    <div class="stat-box">
                        <h3>{self.total_functions}</h3>
                        <p>Functions Scanned</p>
                    </div>
                    <div class="stat-box">
                        <h3>{self.total_issues}</h3>
                        <p>Security Findings</p>
                    </div>
                </div>
            </div>
        """

        # Add Findings Section
        if self.findings:
            html += "<h2>🔍 Security Findings</h2>"
            for finding in self.findings:
                severity = "medium"
                if any(kw in finding['analysis'].lower() for kw in ['critical', 'dangerous', 'severe', 'high', 'eval', 'exec']):
                    severity = "high"
                elif any(kw in finding['analysis'].lower() for kw in ['low', 'minor', 'info']):
                    severity = "low"

                html += f"""
                <div class="finding severity-{severity}">
                    <h3>🔴 {finding['file']} :: {finding['function']}</h3>

                    <h4>📝 Original Code:</h4>
                    <pre>{finding['code']}</pre>

                    <h4>🚨 Security Analysis:</h4>
                    <p>{finding['analysis']}</p>

                    <div class="test-case">
                        <h4>🔬 Test Case:</h4>
                        <pre>{finding['test_case']}</pre>
                    </div>

                    <div class="recommendations">
                        <h4>💡 Recommended Improvements:</h4>
                        <pre>{finding['improvements']}</pre>
                    </div>
                </div>
                """
        else:
            html += """
            <div class="finding severity-low">
                <h3>✅ No Security Issues Found</h3>
                <p>The security scan did not identify any immediate security concerns in the analyzed codebase.</p>
            </div>
            """

        # Add Summary Section
        html += """
            <h2>📋 Summary</h2>
            <div class="overview">
                <p>This security analysis was performed using automated code scanning and LLM-powered analysis.
                While comprehensive, it's recommended to:</p>
                <ul>
                    <li>Review findings manually to confirm their relevance</li>
                    <li>Conduct regular security reviews</li>
                    <li>Implement secure coding practices</li>
                    <li>Consider additional security testing methods</li>
                </ul>
            </div>
        """

        # Add timestamp
        html += f"""
            <div class="timestamp">
                Report generated: {self.timestamp}
            </div>
            </div>
        </body>
        </html>
        """
        return html

def main(codebase_path: str) -> None:
    print("🔍 Indexing codebase...")
    indexer = Indexer(codebase_path)
    code_index = indexer.run()

    # Calculate totals
    total_files = len(code_index)
    total_functions = sum(len(funcs) for funcs in code_index.values())

    print("🔐 Running security analysis...")
    analyzer = SecurityAnalyzer(code_index)
    findings = analyzer.run()

    print("📝 Generating report...")
    reporter = Reporter(
        findings=findings,
        total_files=total_files,
        total_functions=total_functions
    )
    report = reporter.generate_report()

    report_file = "security_report.html"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"Report generated: {report_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python security_tester.py <path_to_codebase>")
        sys.exit(1)
    main(sys.argv[1])
