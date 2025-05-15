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
