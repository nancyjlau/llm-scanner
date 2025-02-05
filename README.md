# llm code snippet analysis

automated llm analysis for python codebases using claude 3 sonnet + openrouter

## what it does
- scans your python codebase for security issues
- uses llm to analyze each function for vulnerabilities
- generates test cases to demonstrate issues
- provides concrete improvement suggestions
- outputs a clean html report

## setup
```bash
export OPENROUTER_KEY="your_key_here"
```

```python
pip install requests
```

## usage
```python
python security_tester.py /path/to/your/codebase
```
<img width="1007" alt="image" src="https://github.com/user-attachments/assets/6175c3c0-f2d4-41ca-b1f1-55de9d2513c9" />


## features
- basic function extraction using ast
- stores source snippets for analysis
- generates html reports with severity levels
- includes test cases + improvement suggestions

## output
- generates security_report.html with:
    - overview stats
    - color-coded findings
    - original code snippets
    - analysis for each issue
    - test cases
    - recommended fixes
