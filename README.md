# DevSecOps-Demo
Repository for testing & validating DevSecOps implementation 

## Assignment 1: Implementing Shift Left Security in CI/CD Pipeline

### Objective: 
Implement security checks early in the development process by integrating them into your CI/CD pipeline using GitHub Actions or GitLab CI.

### Pipelines:
| Security Check for Bookshelf Application (Nodejs) |
| --------------- |
|[![Security Checks](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/security.yaml/badge.svg)](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/security.yaml)|

### What the Pipeline Does
This GitHub Actions pipeline performs automated security checks on your Node.js application located in the bookshelf/ directory. It consists of three main jobs:
* Linting (Code Quality & Syntax Checks)
* Secrets Detection (Secret Leakage Detection)
* Dependency Auditing (Vulnerability Detection)

Each job runs performs specific tasks to ensure the codebase is secure, syntactically correct, and free from obvious security risks.

### Triggers
This workflow is triggered under the following conditions:

* Manually (workflow_dispatch)
* On Pull Request Events: When a pull request is:
  - Opened
  - Reopened
  - Synchronized
* On Push to main branch, only if changes occur in:
  - The `bookshelf/` directory
  - workflow file itself `.github/workflows/security.yaml`

**Note:** If a pull request is labeled `Hot Deployment`, the workflow will skip `Secrets-check` & `Auditing` job
This allows for immediate application releases without blocking on security scans, useful for critical hotfixes or fast deployment cycles. However, it's recommended to perform these checks post-deployment in such cases.

### Job Descriptions and Tools Used

| Security Check | Tool | Description| output |
|----------------|------|------------| ------ |
| Linting Job | ESLint | ESLint is a static code analysis tool for JavaScript. Its primary purpose is to identify and report on patterns found in JavaScript code, the goal is making code more consistent and checking for any syntax errors. | Contains `eslint_report.txt`, showing any linting/syntax issues in tabular format. |
| Secret scanning | Gitleaks | Its purpose was to identify any committed secrets in your Node.js project (bookshelf directory) whenever code was pushed or a pull request was created. If Gitleaks detected any potential secrets. | Contains `gitleaks-report.json`, which lists any detected secrets or credentials in code. |
| Security Vulnerability Check | npm audit | It is a security tool built into Node.js that scans your project's dependencies for known vulnerabilities. Reports issues by severity level (low, moderate, high, critical). | Contains `npm_audit_report.json`, a JSON report of discovered high or critical-level dependency vulnerabilities. |

### Tool selection & criteria
I selected these tools based on several practical and strategic considerations:
* Seamless CI/CD Integration: All tools integrate easily into GitHub Actions, enabling smooth automation without complex setup.
* Open Source & Community-Supported: These are open-source solutions with strong community backing, ensuring transparency, regular updates, and cost-effectiveness.
* Language-Specific Precision: Each tool is optimized for its target language or ecosystem, delivering high accuracy and minimizing false positives.
* Customizability: They support configuration through custom rule sets or config files, allowing fine-tuning to fit our codebase and security policies.
* No Licensing or API Keys Required: These tools run entirely within the CI environment without requiring external API keys, tokens, or paid licenses.
* Purpose-Built for their Use Cases: Each tool is widely adopted and trusted for its specific domain—linting, secrets detection, or dependency auditing—making them reliable for targeted security and quality checks.


## Assignment 2: Enable GHAS for a repository

### Objective:
GitHub Advanced Security features for a repository.

### Pipelines:
| CodeQL Scan for Bookshelf Application (Nodejs) & GitHub Actions workflow|
| --------------- |
|[![CodeQL Advanced Code Check](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/codeql.yml/badge.svg)](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/codeql.yml) |

### What the Pipeline Does
Runs advanced CodeQL analysis weekly and on code changes to detect vulnerabilities in JavaScript/TypeScript and GitHub Actions code.

### Triggers
This workflow is triggered under the following conditions:
* Push to main branch
  - The `bookshelf/` directory
  - workflow file itself `.github/workflows/codeql.yaml`
* Pull request targeting main branch
* Scheduled run every Monday at 00:19 UTC

### Security Analysis and Tools Used

| Security Check        | Tool | Description|
|-----------------------|------|------------|
| Documentation/Process | Policy | A file `(SECURITY.md)` that outlines how users and contributors should report vulnerabilities. It helps standardize and communicate your project's vulnerability disclosure process. |
| Manual Vulnerability Disclosure & Fix Tracking | Security Advisory | Lets maintainers privately disclose, discuss, and patch vulnerabilities in their repositories. Once resolved, advisories can be published as CVEs for public awareness and tracking. |
| Dependency Vulnerability Detection | Dependabot Alerts | Scans the dependency graph of your project against GitHub’s advisory database and alerts you when known vulnerabilities are found in third-party packages. |
| Static Application Security Testing (SAST) | Code Scanning Alerts | Automatically analyzes source code for vulnerabilities and coding errors using CodeQL or third-party tools. Highlights issues like injection flaws, logic errors, and unsafe API usage. |
| Credential & Token Leakage Detection | Type of Check | Detects accidentally committed secrets such as API keys, tokens, or passwords in your Git history or current code and alerts repository maintainers to prevent misuse. |

### Code Scanning Security Report
| Security Check |Vulnerability Description | Severity | Recommended Mitigation Strategy |
|----------------|---------------------------|----------|---------------------------------|
| Code scanning  | Workflow does not contain permissions | Medium | The issue indicates that the GitHub Actions workflow has default (excessive) permissions, which violates the principle of least privilege. To resolve it we can add `permissions` block to our workflow to restrict access.|
| Dependabot Alert | @google-cloud/firestore Logging Issue | Moderate | The alert warns that older versions of the @google-cloud/firestore library (before v6.1.0) & its code dependency. we can upgrade the dependency within `package.json` |


* Permission block added to the workflow 
```
permissions:
  contents: read
```