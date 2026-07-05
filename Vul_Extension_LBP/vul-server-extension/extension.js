const vscode = require('vscode');
const net = require('net');
const fs = require('fs');
const path = require('path');

const crypto = require('crypto');
const { spawn } = require('child_process');

let server = null;
const output = vscode.window.createOutputChannel('Vul Extension');
const diagnostics = vscode.languages.createDiagnosticCollection('vulExtension');
const lastAnalysisByUri = new Map();
let analysisInProgress = false;
let analysisRunCounter = 0;
const vulnerableLineDecoration = vscode.window.createTextEditorDecorationType({
  textDecoration: 'underline wavy rgba(220, 38, 38, 0.95)',
  overviewRulerColor: 'rgba(220, 38, 38, 0.9)',
  overviewRulerLane: vscode.OverviewRulerLane.Right,
});

let analyzeButton = null;
let inferenceServerProcess = null;
let inferenceServerStarting = false;
let inferenceServerReady = false;
let inferenceServerEnvKey = '';
let inferenceServerHost = '127.0.0.1';
let inferenceServerPort = 9079;
const analysisCache = new Map();
const MAX_ANALYSIS_CACHE = 50;

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

function toSortedUniqueIndexes(lines, lineCount, isZeroBased) {
  const mapped = lines
    .map((n) => (isZeroBased ? n : n - 1))
    .filter((idx) => idx >= 0 && idx < lineCount);
  return Array.from(new Set(mapped)).sort((a, b) => a - b);
}

function scoreFindingOverlap(indexes, findings, lineCount) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return 0;
  }

  const findingLines = new Set(
    findings
      .map((item) => Number(item && item.line))
      .filter((n) => Number.isFinite(n))
      .map((n) => Math.trunc(n))
      .filter((n) => n >= 1 && n <= lineCount)
  );

  if (findingLines.size === 0) {
    return 0;
  }

  return indexes.reduce((acc, idx) => acc + (findingLines.has(idx + 1) ? 1 : 0), 0);
}

function normalizeVulnerableLineIndexes(vulnerableLines, lineCount, findings = []) {
  if (!Array.isArray(vulnerableLines) || lineCount <= 0) {
    return { indexes: [], inferredBase: 'one-based' };
  }

  const numericLines = vulnerableLines
    .map((n) => Number(n))
    .filter((n) => Number.isFinite(n))
    .map((n) => Math.trunc(n));

  if (numericLines.length === 0) {
    return { indexes: [], inferredBase: 'one-based' };
  }

  const oneBasedIndexes = toSortedUniqueIndexes(numericLines, lineCount, false);
  const zeroBasedIndexes = toSortedUniqueIndexes(numericLines, lineCount, true);

  if (oneBasedIndexes.length === 0 && zeroBasedIndexes.length === 0) {
    return { indexes: [], inferredBase: 'one-based' };
  }
  if (oneBasedIndexes.length === 0) {
    return { indexes: zeroBasedIndexes, inferredBase: 'zero-based' };
  }
  if (zeroBasedIndexes.length === 0) {
    return { indexes: oneBasedIndexes, inferredBase: 'one-based' };
  }

  const oneScore = scoreFindingOverlap(oneBasedIndexes, findings, lineCount);
  const zeroScore = scoreFindingOverlap(zeroBasedIndexes, findings, lineCount);
  if (oneScore !== zeroScore) {
    if (zeroScore > oneScore) {
      return { indexes: zeroBasedIndexes, inferredBase: 'zero-based' };
    }
    return { indexes: oneBasedIndexes, inferredBase: 'one-based' };
  }

  const hasZeroBasedHint = numericLines.some((n) => n === 0);
  if (hasZeroBasedHint) {
    return { indexes: zeroBasedIndexes, inferredBase: 'zero-based' };
  }

  return { indexes: oneBasedIndexes, inferredBase: 'one-based' };
}

function normalizeFindingLineIndexes(findings, lineCount) {
  if (!Array.isArray(findings) || lineCount <= 0) {
    return [];
  }

  const indexes = findings
    .map((item) => Number(item && item.line))
    .filter((n) => Number.isFinite(n))
    .map((n) => Math.trunc(n) - 1)
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
  const findings = Array.isArray(resultJson && resultJson.findings) ? resultJson.findings : [];
  const findingIndexes = normalizeFindingLineIndexes(findings, doc.lineCount);
  const normalization = normalizeVulnerableLineIndexes(resultJson && resultJson.vulnerable_lines, doc.lineCount, findings);
  const vulnerableIndexes = findingIndexes.length > 0 ? findingIndexes : normalization.indexes;
  const inferredBase = normalization.inferredBase;
  const findingByLine = new Map();
  for (const finding of findings) {
    const rawLine = Number(finding && finding.line);
    if (!Number.isFinite(rawLine)) {
      continue;
    }

    const normalizedLine = inferredBase === 'zero-based'
      ? Math.trunc(rawLine) + 1
      : Math.trunc(rawLine);

    if (normalizedLine >= 1 && normalizedLine <= doc.lineCount) {
      findingByLine.set(normalizedLine, finding);
    }
  }

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
    const finding = findingByLine.get(lineIndex + 1);
    const explanation = finding && typeof finding.explanation === 'string' ? finding.explanation.trim() : '';
    const hoverParts = [`Potentially vulnerable line (model probability: ${probText})`];
    if (finding && finding.title) {
      hoverParts.push(`Type: ${finding.title}`);
    }
    if (explanation) {
      hoverParts.push(`Why: ${explanation}`);
    }


    decorations.push({
      range,
      hoverMessage: hoverParts.join('\n\n'),
    });

    docDiagnostics.push(
      new vscode.Diagnostic(
        range,
        `Potential vulnerability detected by model (probability: ${probText}).`,
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



function hashText(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function buildAnalysisCacheKey(code, mode) {
  const payload = JSON.stringify({ code, mode });
  return hashText(payload);
}

function cacheAnalysisResult(key, result) {
  if (!key) return;
  analysisCache.set(key, { result, storedAt: Date.now() });
  if (analysisCache.size > MAX_ANALYSIS_CACHE) {
    const oldestKey = analysisCache.keys().next().value;
    analysisCache.delete(oldestKey);
  }
}

function getCachedAnalysis(key) {
  if (!key) return null;
  const entry = analysisCache.get(key);
  return entry ? entry.result : null;
}

function getInferenceServerConfig(config) {
  return {
    autoStart: config.get('vulServer.inferenceServerAutoStart', true),
    host: String(config.get('vulServer.inferenceServerHost', '127.0.0.1')),
    port: Number(config.get('vulServer.inferenceServerPort', 9079)),
  };
}

function buildInferenceServerEnvKey(pythonPath, scriptPath) {
  return hashText(JSON.stringify({ pythonPath, scriptPath }));
}

function stopInferenceServer() {
  if (inferenceServerProcess) {
    inferenceServerProcess.kill('SIGTERM');
    inferenceServerProcess = null;
  }
  inferenceServerReady = false;
  inferenceServerStarting = false;
}

async function waitForServerReady(proc, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error('Inference server startup timeout'));
    }, timeoutMs);

    const onData = (data) => {
      const text = String(data || '');
      if (text.includes('SERVER_READY')) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      }
    };

    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);
    proc.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    proc.once('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`Inference server exited early (code ${code})`));
    });
  });
}

async function startInferenceServer(root, config) {
  const pythonPath = config.get('vulServer.pythonPath', '/home/mithilesh/miniconda3/envs/tensorgpu/bin/python');
  const localScriptPath = getConfiguredLocalScript(config);
  const found = findLocalScriptPath(root, localScriptPath);
  const scriptPath = found.scriptPath;

  if (!scriptPath || !fs.existsSync(scriptPath)) {
    const tried = (found.tried || []).map((p) => `  - ${p}`).join('\n');
    throw new Error(`Local script not found. Configured value='${localScriptPath}'. Tried:\n${tried}`);
  }

  const serverCfg = getInferenceServerConfig(config);
  inferenceServerHost = serverCfg.host;
  inferenceServerPort = serverCfg.port;
  const envKey = buildInferenceServerEnvKey(pythonPath, scriptPath);

  if (inferenceServerProcess && inferenceServerReady && inferenceServerEnvKey === envKey) {
    return;
  }

  if (inferenceServerProcess) {
    stopInferenceServer();
  }

  inferenceServerEnvKey = envKey;
  inferenceServerStarting = true;
  inferenceServerReady = false;

  const args = [scriptPath, '--server', '--host', inferenceServerHost, '--port', String(inferenceServerPort)];
  inferenceServerProcess = spawn(pythonPath, args, {
    cwd: path.dirname(scriptPath),
    env: process.env,
  });

  await waitForServerReady(inferenceServerProcess, 60000);
  inferenceServerReady = true;
  inferenceServerStarting = false;
}

function sendServerRequest(payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let buffer = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`Inference server timeout after ${timeoutMs} ms`));
    }, timeoutMs);

    socket.connect(inferenceServerPort, inferenceServerHost, () => {
      socket.write(`${JSON.stringify(payload)}\n`);
    });

    socket.on('data', (data) => {
      buffer += data.toString();
      const idx = buffer.indexOf('\n');
      if (idx >= 0) {
        const line = buffer.slice(0, idx).trim();
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (!line) {
          reject(new Error('Empty response from inference server'));
          return;
        }
        try {
          resolve(JSON.parse(line));
        } catch (err) {
          reject(new Error(`Invalid response from inference server: ${err.message}`));
        }
      }
    });

    socket.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function runLocalInferenceViaServer(root, code) {
  const config = vscode.workspace.getConfiguration();
  const serverCfg = getInferenceServerConfig(config);

  const pythonPath = config.get('vulServer.pythonPath', '/home/mithilesh/miniconda3/envs/tensorgpu/bin/python');
  const localScriptPath = getConfiguredLocalScript(config);
  const found = findLocalScriptPath(root, localScriptPath);
  const scriptPath = found.scriptPath || localScriptPath;
  const envKey = buildInferenceServerEnvKey(pythonPath, scriptPath);
  if (inferenceServerReady && inferenceServerEnvKey && inferenceServerEnvKey !== envKey) {
    stopInferenceServer();
  }

  if (serverCfg.autoStart) {
    if (!inferenceServerReady && !inferenceServerStarting) {
      await startInferenceServer(root, config);
    }
  }

  if (!inferenceServerReady) {
    throw new Error('Inference server is not ready. Start it and try again.');
  }

  const timeoutMs = config.get('vulServer.requestTimeoutMs', 180000);
  const response = await sendServerRequest({ code }, timeoutMs);
  if (!response || response.ok !== true || !response.result) {
    throw new Error(`Inference server error: ${JSON.stringify(response || {})}`);
  }

  return {
    mode: 'local-server',
    raw: { stdout: JSON.stringify(response.result), stderr: response.error || '', code: 0 },
    json: response.result,
  };
}

function shellQuoteSingle(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function buildRemoteEnvPrefix(envMap) {
  return Object.entries(envMap)
    .map(([k, v]) => `${k}=${shellQuoteSingle(v)}`)
    .join(' ');
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
  const env = options.env || process.env;

  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, env });
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
    const first = trimmed.indexOf('{');
    const last = trimmed.lastIndexOf('}');
    if (first >= 0 && last > first) {
      return JSON.parse(trimmed.slice(first, last + 1));
    }
    throw new Error('Failed to parse JSON output from inference process');
  }
}

function getAnalysisKey(document) {
  return document && document.uri ? document.uri.toString() : '';
}

function getStoredAnalysis(editor) {
  if (!editor || !editor.document) {
    return null;
  }
  const key = getAnalysisKey(editor.document);
  if (!key) {
    return null;
  }
  return lastAnalysisByUri.get(key) || null;
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
  if (analysisInProgress) {
    output.appendLine('--- Vul Extension Run ---');
    output.appendLine('Skipped duplicate analysis request while another run is in progress.');
    output.appendLine('--- End of Run ---\n');
    output.show(true);
    vscode.window.showWarningMessage('Vulnerability analysis is already running.');
    return;
  }

  analysisInProgress = true;
  const runId = ++analysisRunCounter;

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    analysisInProgress = false;
    vscode.window.showErrorMessage('No active editor found. Open a source file first.');
    return;
  }

  const code = editor.document.getText();
  if (!code || !code.trim()) {
    analysisInProgress = false;
    vscode.window.showWarningMessage('Active file is empty.');
    return;
  }

  const config = vscode.workspace.getConfiguration();
  const mode = config.get('vulServer.executionMode', 'local');
  const root = getWorkspaceRoot();
  if (!root && mode === 'local') {
    analysisInProgress = false;
    vscode.window.showErrorMessage('No workspace folder open. Local mode needs workspace root.');
    return;
  }

  try {
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Vulnerability analysis (${mode})`,
        cancellable: false,
      },
      async () => {
        try {
          output.appendLine('--- Vul Extension Run ---');
          output.appendLine(`run_id=${runId} | status=started | mode=${mode}`);

        const started = Date.now();
        const cacheKey = buildAnalysisCacheKey(code, mode);
        const cached = getCachedAnalysis(cacheKey);

        const res = cached ? {
          mode: 'cache',
          raw: { stdout: JSON.stringify(cached), stderr: '', code: 0 },
          json: cached,
        } : (mode === 'ssh'
          ? await runSshInference(code)
          : await runLocalInferenceViaServer(root, code));
        const elapsedMs = Date.now() - started;

        const p = typeof res.json.vulnerable_probability === 'number'
          ? `${(res.json.vulnerable_probability * 100).toFixed(2)}%`
          : 'n/a';
        const lineCount = Array.isArray(res.json.vulnerable_lines) ? res.json.vulnerable_lines.length : 0;
        const findings = Array.isArray(res.json.findings) ? res.json.findings : [];
        const detectionMethod = res.json && res.json.detection_method ? String(res.json.detection_method) : 'unknown';

        output.appendLine(`mode=${res.mode} | time=${elapsedMs}ms | prob=${p} | vulnerable_lines=${lineCount} | findings=${findings.length}`);
        output.appendLine(`detection_method=${detectionMethod}`);
        
        output.appendLine('--- End of Run ---\n');
        output.show(true);

        if (!cached) {
          cacheAnalysisResult(cacheKey, res.json);
        }

        lastAnalysisByUri.set(getAnalysisKey(editor.document), {
          ...res.json,
          mode: res.mode,
          analyzedAt: Date.now(),
        });

        applyVulnerabilityHighlights(editor, res.json);
        updateStatusBarButton(Number(res.json.vulnerable_probability));

        const completionMessage = `Vul analysis complete: prob=${p}, lines=${lineCount}, time=${elapsedMs}ms`;
        vscode.window.showInformationMessage(completionMessage);
      } catch (err) {
        clearVulnerabilityHighlights(editor);
        lastAnalysisByUri.delete(getAnalysisKey(editor.document));
        updateStatusBarButton();
        const msg = String(err && (err.stack || err.message) ? (err.stack || err.message) : err);
        output.appendLine('--- Vul Extension Error ---');
        output.appendLine(msg);
        output.show(true);
        vscode.window.showErrorMessage(`Vul analysis failed: ${msg}`);
      }
    }
    );
  } finally {
    analysisInProgress = false;
  }
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

    const runResult = await runLocalInferenceViaServer(root, code);
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

  const analyze = vscode.commands.registerCommand('vulExtension.analyzeActiveEditor', async () => {
    startServer(context);
    await analyzeActiveEditor();
  });
  const analyzeNormal = vscode.commands.registerCommand('vulExtension.runNormalAnalysis', async () => {
    startServer(context);
    await analyzeActiveEditor();
  });
  const start = vscode.commands.registerCommand('vulExtension.startServer', () => startServer(context));
  const stop = vscode.commands.registerCommand('vulExtension.stopServer', () => stopServer());
  const startInference = vscode.commands.registerCommand('vulExtension.startInferenceServer', async () => {
    const root = getWorkspaceRoot();
    if (!root) {
      vscode.window.showErrorMessage('No workspace folder open.');
      return;
    }
    try {
      await startInferenceServer(root, vscode.workspace.getConfiguration());
      vscode.window.showInformationMessage('Inference server started.');
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to start inference server: ${String(err && err.message ? err.message : err)}`);
    }
  });
  const stopInference = vscode.commands.registerCommand('vulExtension.stopInferenceServer', () => {
    stopInferenceServer();
    vscode.window.showInformationMessage('Inference server stopped.');
  });
  context.subscriptions.push(
    analyze,
    analyzeNormal,
    start,
    stop,
    startInference,
    stopInference,
    analyzeButton,
    diagnostics,
    vulnerableLineDecoration,
    output
  );
}

function deactivate() {
  stopServer();
  stopInferenceServer();
}

module.exports = { activate, deactivate };
