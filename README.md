# DevSecOps-Demo
Repository for testing & validating DevSecOps implementation 

## Assignment 1: Implementing Shift Left Security in CI/CD Pipeline

### Objective: 
Implement security checks early in the development process by integrating them into your CI/CD pipeline using GitHub Actions or GitLab CI.

### Pipelines:
| Security Check for Bookshelf Application (Nodejs) |
| --------------- |
|[![Security Checks](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/security.yaml/badge.svg)](https://github.com/MayurManjrekar/DevSecOps-Demo/actions/workflows/security.yaml)|

### Security Check included:

| Security Check | Tool | Description|
|----------------|------|------------|
| Code linting with security rules | ESLint | ESLint is a static code analysis tool for JavaScript. Its primary purpose is to identify and report on patterns found in JavaScript code, the goal is making code more consistent and checking for any syntax errors. |
| Secret scanning | Gitleaks | Its purpose was to identify any committed secrets in your Node.js project (bookshelf directory) whenever code was pushed or a pull request was created. If Gitleaks detected any potential secrets, it would report them in the workflow output and, by default, fail the pipeline to prevent the accidental exposure of sensitive data. |
