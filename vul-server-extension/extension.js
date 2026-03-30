const vscode = require('vscode');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

let server = null;
const output = vscode.window.createOutputChannel('Vul Extension');
const diagnostics = vscode.languages.createDiagnosticCollection('vulExtension');
const vulnerableLineDecoration = vscode.window.createTextEditorDecorationType({
  textDecoration: 'underline wavy rgba(220, 38, 38, 0.95)',
  overviewRulerColor: 'rgba(220, 38, 38, 0.9)',
  overviewRulerLane: vscode.OverviewRulerLane.Right,
});

let analyzeButton = null;

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function getWorkspaceRoot() {
  if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
    return null;
  }
  return vscode.workspace.workspaceFolders[0].uri.fsPath;
}

function resolveScriptPath(root, scriptPathValue) {
  if (!scriptPathValue) return null;
  if (path.isAbsolute(scriptPathValue)) return scriptPathValue;
  if (!root) return scriptPathValue;
  return path.join(root, scriptPathValue);
}

function updateStatusBarButton(probability = null) {
  if (analyzeButton) {
    if (typeof probability === 'number' && Number.isFinite(probability)) {
      const pct = `${(probability * 100).toFixed(2)}%`;
      analyzeButton.text = `$(shield) ${pct}`;
      analyzeButton.tooltip = `Run vulnerability analysis (last probability: ${pct})`;
      return;
    }

    analyzeButton.text = '$(shield)';
    analyzeButton.tooltip = 'Run vulnerability analysis';
  }
}

function normalizeVulnerableLineIndexes(vulnerableLines, lineCount) {
  if (!Array.isArray(vulnerableLines) || lineCount <= 0) {
    return [];
  }

  const numericLines = vulnerableLines
    .map((n) => Number(n))
    .filter((n) => Number.isFinite(n))
    .map((n) => Math.trunc(n));

  if (numericLines.length === 0) {
    return [];
  }

  const hasZeroBasedHint = numericLines.some((n) => n === 0);
  const indexes = numericLines
    .map((n) => (hasZeroBasedHint ? n : n - 1))
    .filter((idx) => idx >= 0 && idx < lineCount);

  return Array.from(new Set(indexes)).sort((a, b) => a - b);
}

function clearVulnerabilityHighlights(editor) {
  if (!editor) return;
  editor.setDecorations(vulnerableLineDecoration, []);
  diagnostics.delete(editor.document.uri);
}

function applyVulnerabilityHighlights(editor, resultJson) {
  if (!editor) return;

  const doc = editor.document;
  const probability = Number(resultJson && resultJson.vulnerable_probability);
  const probText = Number.isFinite(probability)
    ? `${(probability * 100).toFixed(2)}%`
    : 'n/a';
  const vulnerableIndexes = normalizeVulnerableLineIndexes(resultJson && resultJson.vulnerable_lines, doc.lineCount);

  if (vulnerableIndexes.length === 0) {
    clearVulnerabilityHighlights(editor);
    return;
  }

  const decorations = [];
  const docDiagnostics = [];

  for (const lineIndex of vulnerableIndexes) {
    const line = doc.lineAt(lineIndex);
    const startChar = line.firstNonWhitespaceCharacterIndex;
    const endChar = Math.max(line.text.length, startChar + 1);
    const range = new vscode.Range(lineIndex, startChar, lineIndex, endChar);

    decorations.push({
      range,
      hoverMessage: `Potentially vulnerable line (model probability: ${probText})`,
    });

    docDiagnostics.push(
      new vscode.Diagnostic(
        range,
        `Potential vulnerability detected by model (probability: ${probText})`,
        vscode.DiagnosticSeverity.Error
      )
    );
  }

  editor.setDecorations(vulnerableLineDecoration, decorations);
  diagnostics.set(doc.uri, docDiagnostics);
}

function getConfiguredLocalScript(config) {
  return config.get('vulServer.localScriptPathNormal', config.get('vulServer.localScriptPath', 'sing_code.py'));
}

function getConfiguredRemoteScript(config) {
  return config.get('vulServer.remoteScriptPathNormal', config.get('vulServer.remoteScriptPath', '/home/mithilesh/Desktop/vul_extension/sing_code.py'));
}

function findLocalScriptPath(root, configuredScriptPath) {
  const candidates = [];
  const addCandidate = (p) => {
    if (!p) return;
    const normalized = path.normalize(p);
    if (!candidates.includes(normalized)) {
      candidates.push(normalized);
    }
  };

  if (configuredScriptPath) {
    if (path.isAbsolute(configuredScriptPath)) {
      addCandidate(configuredScriptPath);
    } else {
      addCandidate(resolveScriptPath(root, configuredScriptPath));
      addCandidate(path.join(__dirname, configuredScriptPath));
      addCandidate(path.join(__dirname, '..', configuredScriptPath));
      if (root) {
        addCandidate(path.join(root, 'vul_extension', configuredScriptPath));
        addCandidate(path.join(root, 'vul-server-extension', '..', configuredScriptPath));
      }
    }
  }

  addCandidate(path.join(__dirname, '..', 'sing_code.py'));
  addCandidate(path.join(__dirname, '..', 'single_code.py'));
  addCandidate(path.join(__dirname, '..', 'inference_single_code.py'));
  if (root) {
    addCandidate(path.join(root, 'sing_code.py'));
    addCandidate(path.join(root, 'single_code.py'));
    addCandidate(path.join(root, 'inference_single_code.py'));
    addCandidate(path.join(root, 'vul_extension', 'sing_code.py'));
    addCandidate(path.join(root, 'vul_extension', 'single_code.py'));
    addCandidate(path.join(root, 'vul_extension', 'inference_single_code.py'));
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return { scriptPath: candidate, tried: candidates };
    }
  }

  return { scriptPath: null, tried: candidates };
}

function runProcessWithInput(cmd, args, stdinText, options) {
  const timeoutMs = options.timeoutMs || 180000;
  const cwd = options.cwd;

  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd });
    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill('SIGKILL'); } catch (_) {}
      reject(new Error(`Process timeout after ${timeoutMs} ms`));
    }, timeoutMs);

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });

    if (typeof stdinText === 'string') {
      child.stdin.write(stdinText);
    }
    child.stdin.end();
  });
}

function safeJsonParse(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) {
    throw new Error('Empty response from inference process');
  }
  try {
    return JSON.parse(trimmed);
  } catch (_) {
    // Try extracting JSON object boundaries from noisy output
    const first = trimmed.indexOf('{');
    const last = trimmed.lastIndexOf('}');
    if (first >= 0 && last > first) {
      return JSON.parse(trimmed.slice(first, last + 1));
    }
    throw new Error('Failed to parse JSON output from inference process');
  }
}

async function runLocalInference(root, code) {
  const config = vscode.workspace.getConfiguration();
  const pythonPath = config.get('vulServer.pythonPath', 'python3');
  const localScriptPath = getConfiguredLocalScript(config);
  const timeoutMs = config.get('vulServer.requestTimeoutMs', 180000);
  const found = findLocalScriptPath(root, localScriptPath);
  const scriptPath = found.scriptPath;

  if (!scriptPath || !fs.existsSync(scriptPath)) {
    const tried = (found.tried || []).map((p) => `  - ${p}`).join('\n');
    throw new Error(`Local script not found. Configured value='${localScriptPath}'. Tried:\n${tried}`);
  }

  const args = [scriptPath, '--stdin', '--compact-json'];
  const result = await runProcessWithInput(pythonPath, args, code, {
    cwd: path.dirname(scriptPath),
    timeoutMs,
  });
  if (result.code !== 0) {
    throw new Error(`Local inference failed (exit ${result.code}): ${result.stderr || result.stdout}`);
  }

  return {
    mode: 'local',
    raw: result,
    json: safeJsonParse(result.stdout),
  };
}

function buildSshArgs(host, port, user, remoteCmd) {
  return [
    '-p', String(port),
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=10',
    `${user}@${host}`,
    remoteCmd,
  ];
}

async function runSshInference(code) {
  const config = vscode.workspace.getConfiguration();
  const host = config.get('vulServer.sshHost', '10.13.2.9');
  const port = config.get('vulServer.sshPort', 22);
  const user = config.get('vulServer.sshUser', 'mithliesh');
  const remotePython = config.get('vulServer.remotePythonPath', 'python3');
  const remoteScript = getConfiguredRemoteScript(config);
  const timeoutMs = config.get('vulServer.requestTimeoutMs', 180000);
  const allowSshPassword = config.get('vulServer.allowSshPassword', false);

  const remoteCmd = `${remotePython} ${remoteScript} --stdin --compact-json`;
  let cmd = 'ssh';
  let args = buildSshArgs(host, port, user, remoteCmd);

  if (allowSshPassword) {
    const pw = await vscode.window.showInputBox({
      prompt: 'SSH password for backend',
      password: true,
      ignoreFocusOut: true,
    });
    if (!pw) {
      throw new Error('SSH password was not provided');
    }
    cmd = 'sshpass';
    args = ['-p', pw, 'ssh', '-p', String(port), `${user}@${host}`, remoteCmd];
  }

  const result = await runProcessWithInput(cmd, args, code, { timeoutMs });
  if (result.code !== 0) {
    throw new Error(`SSH inference failed (exit ${result.code}): ${result.stderr || result.stdout}`);
  }

  return {
    mode: 'ssh',
    raw: result,
    json: safeJsonParse(result.stdout),
  };
}

async function analyzeActiveEditor() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor found. Open a source file first.');
    return;
  }

  const code = editor.document.getText();
  if (!code || !code.trim()) {
    vscode.window.showWarningMessage('Active file is empty.');
    return;
  }

  const config = vscode.workspace.getConfiguration();
  const mode = config.get('vulServer.executionMode', 'local');
  const root = getWorkspaceRoot();
  if (!root && mode === 'local') {
    vscode.window.showErrorMessage('No workspace folder open. Local mode needs workspace root.');
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Vulnerability analysis (${mode})`,
      cancellable: false,
    },
    async () => {
      try {
        const started = Date.now();
        const res = mode === 'ssh'
          ? await runSshInference(code)
          : await runLocalInference(root, code);
        const elapsedMs = Date.now() - started;

        output.appendLine('--- Vul Extension Run ---');
        output.appendLine(`mode=${res.mode} elapsedMs=${elapsedMs}`);
        output.show(true);

        applyVulnerabilityHighlights(editor, res.json);
        updateStatusBarButton(Number(res.json.vulnerable_probability));

        const p = typeof res.json.vulnerable_probability === 'number'
          ? `${(res.json.vulnerable_probability * 100).toFixed(2)}%`
          : 'n/a';
        const lineCount = Array.isArray(res.json.vulnerable_lines) ? res.json.vulnerable_lines.length : 0;
        vscode.window.showInformationMessage(
          `Vul analysis complete: prob=${p}, lines=${lineCount}, time=${elapsedMs}ms`
        );
      } catch (err) {
        clearVulnerabilityHighlights(editor);
        updateStatusBarButton();
        const msg = String(err && (err.stack || err.message) ? (err.stack || err.message) : err);
        output.appendLine('--- Vul Extension Error ---');
        output.appendLine(msg);
        output.show(true);
        vscode.window.showErrorMessage(`Vul analysis failed: ${msg}`);
      }
    }
  );
}

function startServer(context) {
  const config = vscode.workspace.getConfiguration();
  const port = config.get('vulServer.port', 8765);
  const bindHost = config.get('vulServer.serverBindHost', '127.0.0.1');
  const serverToken = config.get('vulServer.serverAuthToken', '');

  if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
    vscode.window.showErrorMessage('No workspace folder open. Please open the project root.');
    return;
  }

  const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const inputDir = path.join(root, 'input');
  const outputDir = path.join(root, 'output');
  ensureDir(inputDir);
  ensureDir(outputDir);

  if (server) {
    vscode.window.showInformationMessage(`Server already running on port ${port}`);
    return;
  }

  server = net.createServer((socket) => {
    let buffer = '';
    socket.on('data', (data) => {
      buffer += data.toString();
      // Expect newline-delimited JSON messages
      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        let msg = null;
        try {
          msg = JSON.parse(line);
        } catch (e) {
          socket.write(JSON.stringify({ error: 'invalid_json' }) + '\n');
          continue;
        }

        handleMessage(msg, root, inputDir, outputDir, socket, serverToken);
      }
    });

    socket.on('error', (err) => {
      console.error('Socket error', err);
    });
  });

  server.listen(port, bindHost, () => {
    vscode.window.showInformationMessage(`Vul server listening on ${bindHost}:${port}`);
  });

  server.on('error', (err) => {
    vscode.window.showErrorMessage('Server error: ' + String(err));
    server = null;
  });
}

function stopServer() {
  if (server) {
    server.close();
    server = null;
    vscode.window.showInformationMessage('Vul server stopped');
  } else {
    vscode.window.showInformationMessage('Vul server is not running');
  }
}

async function handleMessage(msg, root, inputDir, outputDir, socket, serverToken) {
  try {
    if (serverToken && msg.token !== serverToken) {
      socket.write(JSON.stringify({ ok: false, error: 'unauthorized' }) + '\n');
      return;
    }

    const code = msg.code || msg.text || '';
    const filename = msg.filename || `code_input_${Date.now()}.c`;
    const inputPath = path.join(inputDir, filename);
    fs.writeFileSync(inputPath, code, { encoding: 'utf8' });

    const runResult = await runLocalInference(root, code);
    const stamped = path.join(outputDir, `vul_output_${Date.now()}.json`);
    fs.writeFileSync(stamped, JSON.stringify(runResult.json, null, 2), 'utf8');

    const response = {
      ok: true,
      mode: runResult.mode,
      result: runResult.json,
      stdout: runResult.raw.stdout,
      stderr: runResult.raw.stderr,
      exitCode: runResult.raw.code,
    };
    socket.write(JSON.stringify(response) + '\n');

  } catch (err) {
    const e = String(err.stack || err.message || err);
    socket.write(JSON.stringify({ ok: false, error: e }) + '\n');
  }
}

function activate(context) {
  analyzeButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  analyzeButton.command = 'vulExtension.analyzeActiveEditor';
  analyzeButton.show();

  updateStatusBarButton();

  const analyze = vscode.commands.registerCommand('vulExtension.analyzeActiveEditor', () => analyzeActiveEditor());
  const analyzeNormal = vscode.commands.registerCommand('vulExtension.runNormalAnalysis', () => analyzeActiveEditor());
  const start = vscode.commands.registerCommand('vulExtension.startServer', () => startServer(context));
  const stop = vscode.commands.registerCommand('vulExtension.stopServer', () => stopServer());
  context.subscriptions.push(
    analyze,
    analyzeNormal,
    start,
    stop,
    analyzeButton,
    diagnostics,
    vulnerableLineDecoration,
    output
  );
}

function deactivate() {
  stopServer();
}

module.exports = { activate, deactivate };
