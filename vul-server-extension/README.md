# Vul Extension

This extension analyzes source code for vulnerabilities by invoking your Python inference pipeline.

It supports two execution modes:
- Local mode: runs Python script on the same machine as VS Code.
- SSH mode: sends code over SSH and runs Python script on remote backend.

## Commands

- Vul Extension: Analyze Active Editor
- Vul Extension: Run Normal Analysis
- Vul Server: Start
- Vul Server: Stop

## Core Workflow

Analyze Active Editor command:
1. Reads full text from active editor.
2. Sends code to inference process through stdin.
3. Parses JSON from stdout.
4. Highlights vulnerable lines with red underline in the active editor.
5. Updates shield status bar button with latest vulnerability probability.
6. Shows summary notification and full JSON in output channel.

Editor toolbar button:
- A shield icon appears in the top-right editor toolbar.
- Clicking it runs Vulnerability Analysis on the active editor.

Status bar button:
- A single shield icon appears in the status bar.
- Clicking it runs normal vulnerability analysis.
- After each run it shows the latest vulnerability probability percentage.

No shared code_input.txt file is required.

## Extension Settings

- vulServer.executionMode: local or ssh
- vulServer.pythonPath: local python executable
- vulServer.localScriptPath: local inference script path
- vulServer.localScriptPathNormal: local normal analysis script
- vulServer.sshHost: SSH host
- vulServer.sshPort: SSH port
- vulServer.sshUser: SSH username
- vulServer.remotePythonPath: remote python executable
- vulServer.remoteScriptPath: remote inference script path
- vulServer.remoteScriptPathNormal: remote normal analysis script
- vulServer.allowSshPassword: allow password auth via sshpass fallback
- vulServer.serverBindHost: TCP server bind interface
- vulServer.serverAuthToken: optional token for TCP server auth
- vulServer.requestTimeoutMs: request timeout
- vulServer.showRawJson: print full JSON in output channel

## Local Testing

Prerequisites:
- Python dependencies installed for inference script
- Workspace contains inference_single_code.py

Steps:
1. Open this extension folder in VS Code.
2. Press F5 to launch Extension Development Host.
3. Open a source file in the new window.
4. Run command: Vul Extension: Analyze Active Editor.

## SSH Backend Testing

Recommended: SSH key authentication.

If you must use password auth:
- set vulServer.allowSshPassword = true
- ensure sshpass is installed on local machine
- extension prompts for password at run time and does not persist it

Remote backend requirements:
- remote host reachable via SSH
- Python and model dependencies installed remotely
- remote inference script path valid
- script supports: --stdin --compact-json

## Marketplace Readiness Notes

Before publishing:
1. Test local mode and ssh mode on clean machine.
2. Add icon, categories, repository metadata to package.json.
3. Add CHANGELOG.md and LICENSE.
4. Package with vsce and run install test.

## Deployment (Marketplace)

1. Set package metadata in package.json: publisher, repository, icon, categories, keywords.
2. Install packaging tool: npm install -g @vscode/vsce.
3. Build package: vsce package.
4. Publish: vsce publish.

For production backend:
- prefer SSH key auth over password.
- configure remoteScriptPathNormal.

## Connection Model

Local mode:
- extension spawns python locally and streams active editor code via stdin.

SSH mode:
- extension opens SSH process and executes remote python script.
- active editor code is piped to remote script stdin.

No shared code_input.txt is required in either mode.

## Can Any Client Connect To My Server?

TCP server behavior:
- if serverBindHost is 0.0.0.0, external clients can connect.
- default serverBindHost is 127.0.0.1, so only local machine clients can connect.
- if serverAuthToken is set, each TCP message must include token field.

## Legacy TCP Server

The TCP server commands are still available for custom integrations.
