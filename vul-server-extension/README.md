# Vul Extension

This extension analyzes source code for vulnerabilities by invoking your Python inference pipeline.

It supports two execution modes:
- Local mode: runs Python script on the same machine as VS Code.
- SSH mode: sends code over SSH and runs Python script on remote backend.

Local mode can use a persistent inference server to avoid cold starts and keep caches warm.

## Commands

- Vul Extension: Analyze Active Editor
- Vul Extension: Run Normal Analysis
- Vul Extension: Apply Suggested Fix
- Vul Server: Start
- Vul Server: Stop
- Vul Inference Server: Start
- Vul Inference Server: Stop

## Core Workflow

Analyze Active Editor command:
1. Reads full text from active editor.
2. Ensures Vul Server is started, then sends code to the persistent inference server.
3. Parses JSON from stdout.
4. Highlights vulnerable lines with red underline in the active editor.
5. Updates shield status bar button with latest vulnerability probability.
6. Shows summary notification and run details in output channel.
7. If findings exist, offers a Choose Fix action.

Apply Suggested Fix command:
1. Opens a picker for findings from the latest analysis of the current file.
2. Lets user choose one of the generated fix suggestions.
3. Calls the configured Ollama endpoint (cloud-first model selection) to generate structured patch candidates for the selected finding.
4. Shows patch candidates for selection, then asks explicit approval before applying any edit.
5. Offers a one-click re-run of analysis after the edit.

## UI Elements

Editor toolbar buttons:
- Shield icon: run vulnerability analysis on active editor.
- Tools icon: open suggested fix picker for latest findings.

Status bar button:
- Shield icon displays last vulnerability probability.
- Click to run normal vulnerability analysis.

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
- vulServer.ragEnabled: enable retrieval-augmented findings
- vulServer.ragTopK: retrieval evidence count per line
- vulServer.ragMaxLines: max enriched vulnerable lines
- vulServer.ragWindow: context window around each vulnerable line
- vulServer.ragCache: cache RAG findings in current extension session
- vulServer.staticRulesEnabled: enable additional static-rule findings
- vulServer.staticMaxFindings: max static findings merged per file
- vulServer.ragBudgetMs: total RAG stage budget
- vulServer.llmEnabled: enable LLM explanation/fix generation
- vulServer.llmProvider: LLM backend provider
- vulServer.ollamaUrl: local ollama endpoint
- vulServer.ollamaCloudUrl: cloud ollama endpoint
- vulServer.ollamaApiKey: optional cloud API key
- vulServer.ollamaModel: primary local model
- vulServer.useCloudModel: use cloud model preference
- vulServer.ollamaCloudModel: primary cloud model
- vulServer.ollamaLocalFallbacks: local fallback models
- vulServer.ollamaCloudFallbacks: cloud fallback models
- vulServer.llmTimeoutMs: per-line LLM timeout
- vulServer.llmTemperature: LLM temperature
- vulServer.showRawJson: print full JSON response in output channel
- vulServer.port: TCP server port
- vulServer.inferenceServerAutoStart: auto-start the inference server when needed
- vulServer.inferenceServerHost: host for the inference server
- vulServer.inferenceServerPort: port for the inference server

## Full Setup (Step-by-Step)

1. Create or activate your Python environment with model dependencies.
2. Install all model dependencies required by inference_single_code.py (transformers, torch, captum, etc.).
3. Install Joern and ensure `joern` and `joern-parse` are on PATH.
4. Verify inference_single_code.py paths to model checkpoints are valid on this machine.
5. Open this extension folder in VS Code.
6. Press F5 to launch Extension Development Host.
7. In the extension host, open a source file to analyze.
8. Set these settings (User or Workspace settings):
	- vulServer.executionMode = local
	- vulServer.pythonPath = /path/to/python
	- vulServer.localScriptPath = /path/to/inference_single_code.py
	- vulServer.inferenceServerAutoStart = true
9. Run command: Vul Extension: Analyze Active Editor.
10. If prompted, start the inference server via Vul Inference Server: Start.

## Fast Path (Persistent Server)

Recommended for performance.

1. Keep vulServer.inferenceServerAutoStart = true.
2. Run Vul Extension: Analyze Active Editor.
3. The extension will start the Python server once and reuse it for future requests.

## Local Testing

Prerequisites:
- Python dependencies installed for inference script
- Workspace contains inference_single_code.py

Steps:
1. Open this extension folder in VS Code.
2. Press F5 to launch Extension Development Host.
3. Open a source file in the new window.
4. Run command: Vul Extension: Analyze Active Editor.
5. If findings are reported, click Choose Fix or run Vul Extension: Apply Suggested Fix.

## SSH Backend Testing

Recommended: SSH key authentication.

If you must use password auth:
- set vulServer.allowSshPassword = true
- ensure sshpass is installed on local machine

Remote backend requirements:
- remote host reachable via SSH
- Python and model dependencies installed remotely
- remote inference script path valid
- script supports: --stdin --compact-json

## Connection Model

Local mode:
- extension uses a persistent Python server when enabled, otherwise spawns Python locally per run.

SSH mode:
- extension opens SSH process and executes remote Python script.
- active editor code is piped to remote script stdin.

No shared code_input.txt is required in either mode.

## Legacy TCP Server

TCP server commands are still available for custom integrations.
