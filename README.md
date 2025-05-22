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


## Assignment 4: Using SonarQube for SAST capabilities

### Objective: 
Integrate SonarQube and upload the reports.

### What is SonarQube? 
SonarQube is an open-source platform for continuous inspection of code quality. It provides static analysis of your code to identify potential issues, such as:
* Bugs 
* Vulnerabilities 
* Code Smells (bad practices or poor maintainability)
* Duplications 

**Metrics & Reports:**
Generates detailed reports on code quality and security issues. Displays quality gates for each project (e.g., whether your code meets the defined quality standards).


### What is Gradle?
Gradle is a powerful open-source build automation tool used primarily for:
* Compiling code
* Running tests
* Packaging applications
* Managing dependencies
* Running quality checks (like SonarQube analysis)

### Prerequisites
* Docker
* Java JDK (>=11)
* Gradle (>=8.x)
* VS Code or preferred IDE

### Step 1: Install & Run Docker
* Install Docker Desktop
* Download and [install Docker](https://docs.docker.com/desktop/setup/install/mac-install/)

### Step 2: Run SonarQube in Docker
* Open a terminal and run the following command:
```
docker pull sonarqube
docker run --name sonarqube-custom -p 9000:9000 sonarqube
```
* Access SonarQube, Open your browser and visit:
```
http://localhost:9000
```

* Login (First time only):
```
Username: admin
Password: admin
```

* Change the password.


### Step 3: Installing Dependencies
* Install Homebrew
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

* Install Java:
```
brew install openjdk@17
export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
export PATH="$JAVA_HOME/bin:$PATH"
```

* Install Gradle:
```
brew install gradle
```

* Install Node.js and npm
```
brew install node
```


### Step 4: Create build.gradle for Your Project
* In your project directory, create a build.gradle file with the following content:
```
plugins {
    id 'org.sonarqube' version '3.3'
    id 'java' // If you have Java code in the project as well
}

repositories {
    mavenCentral()  // This ensures Gradle can download dependencies from Maven Central
}

sonarqube {
    properties {
        property "sonar.projectKey", "bookshelf-app"
        property "sonar.organization", "DevSecOps-Demo"
        property "sonar.host.url", "http://localhost:9000"
        property "sonar.token", project.findProperty("sonar.token") ?: System.getenv("SONAR_TOKEN")

        // Specify the source directories for JavaScript
        property "sonar.sources", "books, lib"  // Include the JS code directories
        property "sonar.tests", "test"  // Your test directory

        // coverage report path
        property "sonar.javascript.lcov.reportPaths", "build/reports/tests/lcov.info"
    }
}

dependencies {
    testImplementation 'org.junit.jupiter:junit-jupiter:5.9.3' // Keep it if you're using JUnit for other tests

    // You may add additional dependencies related to JS testing frameworks if required
}

test {
    useJUnitPlatform()
}
```
#### Test Case file 
* `test/app.test.js`
```
const app = require('../app');

const request = require('supertest');

describe('Requests have valid status codes', () => {
  it('should get 302', (done) => {
    request(app).get('/').expect(302, done);
  }),
    it('should get books', (done) => {
      request(app).get('/books').expect(200, done);
    });
  it('should get books/add form', (done) => {
    request(app).get('/books/add').expect(200, done);
  });
});

describe('Should have logs and errors endpoints as described in docs for Stackdriver', () => {
  it('should have logs endpoints', (done) => {
    request(app).get('/logs').expect(200, done);
  }),
    it('should have errors endpoint', (done) => {
      request(app).get('/errors').expect(500, done);
    });
});
```

### Step 5: Set Up SonarQube Authentication Token
* Generate Token:
* In SonarQube UI: Go to My Account > Security > Generate Token.
* Set SONAR_TOKEN Environment Variable:
```
export SONAR_TOKEN="<your_generated_token>"
```

### Step 6: Run SonarQube Analysis
* Generates test and coverage reports 
```
npm run test -- --coverage
```

* From your project directory, run:  Builds the app and uploads analysis + coverage to SonarQube
```
gradle build sonarqube
```

##### Gradle Command: `gradle clean build sonarqube`

| Command Part         | Description    | Purpose   |
|----------------------|----------------|-----------|
| `build`    | Compiles the source code, runs unit tests, and creates output artifacts | Validates that the code builds correctly and tests pass    |
| `sonarqube`| Analyzes code quality and uploads results to the SonarQube server       | Identifies bugs, code smells, and vulnerabilities in your codebase   |


### Report

#### Summary

| Metric                | Description   |  Status          |
| --------------------- | ------------- | ---------------- |
| **Security**          | Checks for known vulnerabilities and insecure code | A (0 issues)       |
| **Reliability**       | Detects bugs and runtime failure risks             | A (0 issues)       |
| **Maintainability**   | Detects code smells affecting maintainability      | A (2 issues)       |
| **Coverage**          | Shows how much of the code is covered by tests     | 35.7% (109 lines) |
| **Duplications**      | Highlights repeated code                           | 0.0%               |
| **Security Hotspots** | Sensitive code that may need manual review         | 0 hotspots         |
| **Accepted Issues**   | Valid issues intentionally left unresolved         | 0 accepted         |


#### SonarQube UI
![SonarQube UI](Images/Sonarqube-ui.png)

#### SonarQube Report
![Sonarqube-report](Images/Sonarqube-report.png)

#### Dectected Issues
![Sonarqube Vulnerability](Images/Sonarqube-vulnerability-report.png)
![Issue Description](Images/Report-description.png)

### Reference
* [Download Docker](https://docs.docker.com/desktop/setup/install/mac-install/)
* [Sonar analysis Meduim Post](https://allancarneirosantos.medium.com/how-to-get-full-sonar-analysis-from-local-code-8284a883149e)
* [SonarQube commands](https://docs.gradle.org/8.14/userguide/command_line_interface.html#sec:command_line_warnings)


## Assignment 5: Integrating SCA in CI pipeline

### Objective:
Implement Software Composition Analysis (SCA) to identify and manage vulnerabilities in open-source components and report the findings.

### What is Software Composition Analysis (SCA)?
Software Composition Analysis (SCA) is a process of identifying and managing the open-source components and dependencies used in a software project. It helps understand the security, license, and quality risks associated with third-party software.
Key Features of SCA:
* Dependency Scanning:
* Vulnerability Detection:
* License Compliance: Checks for open-source license compliance to avoid legal risks.
* Version Management: Alerts you to outdated or vulnerable versions of libraries.
* Supply Chain Security: Detects malicious or compromised packages in your supply chain.

### What is SBOM ?
SBOM (Software Bill of Materials) is a comprehensive inventory of all components, libraries, and dependencies within a software project. It provides transparency into the software's composition, aiding in vulnerability management, license compliance, and supply chain security
```
snyk sbom --format=cyclonedx1.6+json --all-projects --json-file-output=mysbom.json
```
**Note:** The snyk sbom command is designed to generate a Software Bill of Materials (SBOM) for your project. However, this functionality is exclusive to customers on Snyk Enterprise plans.

### Pipelines:
| SCA Scan using Snyk|
| --------------- |
| [![Snyk Security Scan](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/snyk-scan.yaml/badge.svg)](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/snyk-scan.yaml) |

### Triggers:
The workflow is triggered on:
* Manually (workflow_dispatch)
* On Pull Request Events: When a pull request is:
  - Opened
  - Reopened
  - Synchronized (when new commits are pushed to the pull request branch)
* On Push to main branch, only if changes occur in:
  - The `bookshelf/` directory
  - workflow file itself `.github/workflows/snyk-scan.yaml`

### Workflow Permissions Block:
```
permissions:
  contents: read
  security-events: write
  actions: read
```
* contents: read - Allows the workflow to read your repository’s files.
* security-events: write - Required to upload SARIF files to GitHub Security Dashboard.
* actions: read - Allows the workflow to run GitHub Actions.

**Note:** To publish SARIF files to `GitHub Security`, you also need to enable Code Scanning for your repository in the settings.

### Commands: 
| **Feature** | **`snyk test`** | **`snyk monitor`** |
|--------------|-----------------|--------------------|
| **Purpose** | Immediate security testing | Long-term vulnerability monitoring |
| **Output** | CLI results, JSON, SARIF | Snyk dashboard |
| **Alerts** | No | Yes, continuous alerts |
| **Impact on Snyk Dashboard** | No project created | Creates a project for ongoing monitoring |
| **Typical Use** | CI/CD pipelines, local testing | Continuous security monitoring |
| **Common Options** | `--json`, `--sarif-file-output`, `--all-projects` | `--project-name`, `--tags`, `--all-projects` |


### Setting Up Snyk
### Step 1: Create a Snyk Account
1. Go to [Snyk.io](https://snyk.io/) and create a free account.
2. Complete the sign-up process using your email or GitHub

### Step 2: Generate Snyk API Token
1. Once logged in, go to the Settings page.
2. Click on "API Token".
3. Click "Generate" to create a new API token.
4. Copy the generated token.

![API Token](Images/snyk-api-token.png)

### Step 3: Store the API Token in GitHub Secrets
1. Go to your GitHub repository.
2. Navigate to Settings → Secrets and variables → Actions → New repository secret.
3. Set the Name as SNYK_TOKEN.
4. Paste the copied API token as the Value.

### Step 4: Reference the Token in Your Workflow
Add the following env block in your GitHub Actions workflow to use the Snyk token:
```
env:
  SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

### Step 5: Setting up Snyk for CLI (Vs code editor)
1. Install the Snyk CLI
```
npm install -g snyk
```

2. Authenticate with Snyk: This will open a browser window where you can log in to your Snyk account.
```
snyk auth
```


### SBOM Report
| **Name**         | **Version** | **License** | **PURL**                         |
| ---------------- | ----------- | ----------- | -------------------------------- |
| express          | 4.21.2      | MIT         | `pkg:npm/express@4.21.2`         |
| lodash.camelcase | 4.3.0       | MIT         | `pkg:npm/lodash.camelcase@4.3.0` |
| fast-deep-equal  | 3.1.3       | MIT         | `pkg:npm/fast-deep-equal@3.1.3`  |
| google-gax       | 2.30.5      | Apache-2.0  | `pkg:npm/google-gax@2.30.5`      |
| body-parser      | 1.20.3      | MIT         | `pkg:npm/body-parser@1.20.3`     |

### Vulnerability Report
| Severity | Vulnerability Description | Affected Package(s) & Version(s) | Remediation Recommendation | |
| -------- | ------------------------- | -------------------------------- | -------- | ----------------- |
| Medium   | Insecure Storage of Sensitive Information  | `@google-cloud/firestore` v5.0.2  | Upgrade to `@google-cloud/firestore` v6.2.0 or higher. |  |
| High     | Prototype Pollution (CVE-2023-36665)  | `protobufjs` v6.11.3 (via `google-gax` > `protobufjs`)       | Upgrade `protobufjs` to v6.11.4, v7.2.4, or higher. |    |
| High     | Denial of Service (DoS) (CVE-2022-24434)  | `dicer` v0.2.5 (via `busboy` > `dicer`)   | Upgrade `multer` to v1.4.5-lts.1 or higher. |   |
| High     | Uncaught Exception  | `multer` v1.4.4 | Upgrade to `multer` v1.4.5-lts.1 or higher. |  |
| High     | Missing Release of Memory after Effective Lifetime | `multer` v1.4. | Upgrade to `multer` v1.4.5-lts.1 or higher.  |  |
| Medium   | Uncontrolled Resource Consumption (CVE-2024-37168) | `@grpc/grpc-js` v1.6.12 (via `google-gax` > `@grpc/grpc-js`) | Upgrade `@grpc/grpc-js` to v1.8.22, v1.9.15, v1.10.9, or higher.  | |

### Resolving `Insecure Storage of Sensitive Information ` Vulnerability
* Update @google-cloud/firestore to version 6.2.0 or higher:
```
npm install @google-cloud/firestore@^6.2.0
```

* Proof of concept

![Snyk before resolving issue](Images/snyk-before-resolving-vulnerability.png)

![Snyk after resolving issue](Images/snyk-after-resolving-vulnerability.png)

### Snyk UI
![Snyk UI](Images/snyk-project-ui.png)

### Snyk UI Logs
![Snyk UI Logs](Images/snyk-report-ui.png)

### Workflow log
![Snyk workflow log](Images/snyk-workflow-log.png)

### Github Security Published log
![Snyk Github](Images/snyk-github-report.png)

### Published Report
![JSON Report](Images/snyk-json-report.png)

### References
* [Snyk Actions](https://github.com/snyk/actions/tree/master/node)
* [Snyk CLI Commands](https://docs.snyk.io/snyk-cli/cli-commands-and-options-summary)
* [Snyk SBOM](https://snyk.io/blog/creating-sboms-snyk-cli/)


## Assignment 6: Image Scanning
### Objective: 
Implement image scanning into the CI/CD pipeline to ensure container image security.

| Docker Image Scan using Snyk & Trivy|
| --------------- |
|[![Docker Image Scan](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/docker-scan.yaml/badge.svg)](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/docker-scan.yaml)|


### Snyk
Snyk is a security platform that helps identify and fix vulnerabilities in container images. It scans container images through the Snyk Web UI, CLI, or integrations with container registries like Docker Hub. Snyk provides detailed reports on vulnerabilities found in base images and application dependencies, along with actionable remediation advice, such as opening fix pull requests or suggesting image upgrades.

### Trivy
Trivy is an open-source vulnerability scanner developed by Aqua Security, designed to detect security issues in container images, file systems, and repositories. It scans for known vulnerabilities (CVEs) in OS packages and application dependencies, as well as misconfigurations and secrets. Trivy is known for its ease of use, requiring minimal setup, and can be integrated into CI/CD pipelines to automate security checks. 

### Docker Image Vulnerability Scan Workflow
This GitHub Actions workflow is designed to **scan Docker images for security vulnerabilities** using **Snyk**, upload the results to the **GitHub Security Dashboard**, **Snyk Dashboard** and save a detailed **HTML report** as a build artifact.

### Features:
- **Docker Image Build:** Builds the Docker image for the **`bookshelf-app`**.
- **Snyk Vulnerability Scanning:** Scans the Docker image for known vulnerabilities.
- **SARIF Upload:** Publishes the scan results to the GitHub Security Dashboard.
- **Snyk Monitoring:** Uploads scan results to the Snyk dashboard for continuous monitoring.
- **HTML Report Generation:** Converts JSON output to a readable HTML report for easier analysis.

### Triggers:
The workflow is triggered on:
* Manually (workflow_dispatch)
* On Pull Request Events: When a pull request is:
  - Opened
  - Reopened
  - Synchronized (when new commits are pushed to the pull request branch)
* On Push to main branch, only if changes occur in:
  - The `bookshelf/` directory
  - workflow file itself `.github/workflows/docker-scan.yaml`

### Commands 
1. Snyk test command:
```
snyk container test ${{env.IMAGE_NAME}} --file=./bookshelf/Dockerfile --project-name=Bookshelf-App --sarif-file-output=./snyk.sarif --severity-threshold=high --json | snyk-to-html -o bookshelf-scan.html 
```
```
#CLI Command
snyk container test sample-app \     
  --file=dockerfile \
  --json \
  | snyk-to-html -o snyk-report.html
```

| **Component**  | **Description** |  
| ---------------|-----------------|
| `snyk container test` | security scan on the specified container image to detect known vulnerabilities. |  
| `${{env.IMAGE_NAME}}` | References the environment variable `IMAGE_NAME`,Docker image to be scanned. | 
| `--file=./bookshelf/Dockerfile` | Provides the path to the Dockerfile used to build the image.|
| `--project-name=Bookshelf-App` | Assigns a custom name, "Bookshelf-App", to the project within Snyk. |
| `--sarif-file-output=./snyk.sarif` | Outputs the scan results in SARIF (Static Analysis Results Interchange Format) to the specified file. To publish the report in GitHub security dashboard |
| `--severity-threshold=high` | Filters the scan results to include only vulnerabilities with a severity of "high" or "critical".|
| `--json`  | Outputs the scan results in JSON format to the standard output.| 
| `snyk-to-html -o bookshelf-scan.html` | Pipes the JSON output into the `snyk-to-html` tool, which converts the JSON data into a human-readable HTML report saved as `bookshelf-scan.html`. |

2. Snyk authentication:
```
snyk auth ${{ secrets.SNYK_TOKEN }}
```
Authenticates the Snyk CLI using a token stored securely in GitHub Actions secrets, allowing subsequent Snyk commands to access the user’s Snyk account and perform vulnerability scans.

3. Trivy test Command:

| **Component**    | **Description**                                                                                   |
|------------------|---------------------------------------------------------------------------------------------------|
| `image-ref`      | The container image to be scanned for vulnerabilities.                                            |
| `format`         | Defines the format of the vulnerability scan output (e.g., table, json, sarif).                   |
| `exit-code`      | Determines which exit code to return if vulnerabilities are found; used for controlling workflow. |
| `output`         | Specifies the file where the scan results will be saved.                                          |
| `ignore-unfixed` | Ignores vulnerabilities that don’t have a fix yet, reducing noise in reports.                     |
| `vuln-type`      | Indicates the types of vulnerabilities to scan for (e.g., OS packages, libraries).                |
| `severity`       | Filters scan results to include only specified severity levels (e.g., HIGH, CRITICAL).            |

4. Docker commands:

* Build docker image
```
docker build -t IMAGE_NAME ./DIRECTORY/PATH
```

* Run docker image
```
docker run -d -p 3000:3000 IMAGE_NAME
```



## Report 
| Vulnerability Type   | Affected Package  | Debian Version | CVE ID   | Remediation  |
|----------------------|-------------------|----------------|----------|--------------|
| Integer Overflow / Wraparound | zlib/zlib1g                     | Debian 10      | CVE-2023-45853      |  No fix in Debian 10.  Switch to Debian 11+ or remove the package.       |
| XML External Entity (XXE)     | python3.7/libpython3.7-stdlib   | Debian 10      | CVE-2022-48565      | Upgrade to `python3.7` version `3.7.3-2+deb10u6` or later.                |
| Buffer Overflow               | python2.7/libpython2.7-stdlib   | Debian 10      | CVE-2021-3177       | Upgrade to `python2.7` version `2.7.16-2+deb10u2`.  |
| XML External Entity (XXE)     | python2.7/libpython2.7-stdlib   | Debian 10      | (XXE variant)        | Remove or upgrade Python 2.7 where possible; Python 2 is deprecated.      |


### Resolving critical Vulnerabilities in Docker Image
* Update base image from `node:14` to `node:18-slim`

* Proof of concept

![Docker Snyk before resolving issue](Images/docker-snyk-old-report.png)

![Docker Snyk after resolving issue](Images/docker-snyk-slim-report.png)

### Resolving `Integer Overflow / Wraparound` Vulnerability
* Update base image from `node:18-slim` to `node:18-alpine`

* Proof of concept

![Docker Snyk after resolving issue](Images/docker-snyk-slim-report.png)

![Docker Snyk after resolving issue](Images/docker-snyk-alpine-report.png)

### Snyk UI
![Docker Snyk UI Project](Images/docker-snyk-ui-project.png)
![Docker Snyk UI](Images/docker-snyk-ui-report.png)

### Snyk UI Logs
![Docker Snyk UI Report](Images/docker-snyk-ui-report-2.png)

### Workflow log
![Docker Snyk workflow log](Images/docker-snyk-workflow-log.png)
![Docker Trivy workflow log](Images/docker-trivy-workflow-log.png)

### Github Security Published log
![Docker Snyk Github](Images/docker-snyk-github-security-report.png)

### Snyk Published Report
![Docker HTML Report](Images/docker-snyk-html-report.png)

### Trivy Published Report
![Trivy Docker JSON Report](Images/docker-trivy-json-report.png)

### Snyk Email Notification
![Docker Snyk Notification setting](Images/docker-snyk-email-notification-setting.png)
![Docker Snyk Email Notification](Images/docker-snyk-email-alert.png)

### References
* [Snyk Actions](https://github.com/snyk/actions/tree/master/node)
* [Snyk CLI Commands](https://docs.snyk.io/snyk-cli/cli-commands-and-options-summary)
* [Trivy Actions](https://github.com/aquasecurity/trivy-action)
* [Snyk Docker](https://docs.snyk.io/scan-with-snyk/snyk-container/use-snyk-container/detect-the-container-base-image)