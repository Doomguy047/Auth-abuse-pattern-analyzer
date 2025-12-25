# Authentication Abuse Pattern Analyzer

## Overview
This project analyzes authentication log data to identify common abuse patterns such as password spraying and brute-force attacks using evidence from login behavior.

## Problem Statement
Authentication abuse is a frequent real-world attack vector. Understanding how these attacks manifest in authentication logs is essential for effective detection and incident response.

## Approach
- Parse authentication logs (CSV format)
- Include normal and noisy authentication behavior
- Identify failure-based patterns using thresholds
- Classify abuse types with evidence-backed logic
- Output structured analysis results
- Authentication failures are correlated within a fixed time window to distinguish concentrated attack activity from long-term noise.

## How to Run
```bash
python3 analyzer.py
