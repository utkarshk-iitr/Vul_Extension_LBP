const vscode = require('vscode');
const net = require('net');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');

function loadEnvFile(envPath) {
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}
loadEnvFile(path.join(__dirname, '.env'));

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
    const fix = finding && Array.isArray(finding.fix_suggestions) && finding.fix_suggestions.length > 0
      ? String(finding.fix_suggestions[0].summary || '').trim()
      : '';
    const explanation = finding && typeof finding.explanation === 'string'
      ? finding.explanation.trim()
      : '';

    const hoverParts = [`Potentially vulnerable line (model probability: ${probText})`];
    if (finding && finding.title) {
      hoverParts.push(`Type: ${finding.title}`);
    }
    if (explanation) {
      hoverParts.push(`Why: ${explanation}`);
    }
    if (fix) {
      hoverParts.push(`Fix: ${fix}`);
    }

    decorations.push({
      range,
      hoverMessage: hoverParts.join('\n\n'),
    });

    const fixSuffix = fix ? ` Suggested fix: ${fix}` : '';

    docDiagnostics.push(
      new vscode.Diagnostic(
        range,
        `Potential vulnerability detected by model (probability: ${probText}).${fixSuffix}`,
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

function normalizeOllamaGenerateUrl(rawUrl) {
  const input = String(rawUrl || '').trim();
  if (!input) {
    return '';
  }

  try {
    const parsed = new URL(input);
    const pathname = String(parsed.pathname || '').replace(/\/+$/, '');
    if (pathname === '' || pathname === '/') {
      parsed.pathname = '/api/generate';
      return parsed.toString();
    }
    if (pathname === '/api') {
      parsed.pathname = '/api/generate';
      return parsed.toString();
    }
    return parsed.toString();
  } catch (_) {
    return input;
  }
}

function buildRagEnv(config) {
  const useCloud = config.get('vulServer.useCloudModel', true);
  const ollamaModel = String(config.get('vulServer.ollamaModel', 'qwen2.5-coder:3b'));
  const cloudModel = String(config.get('vulServer.ollamaCloudModel', 'gpt-oss:120b-cloud'));
  const localUrl = Object.is(useCloud, false) ? normalizeOllamaGenerateUrl(config.get('vulServer.ollamaUrl', 'http://127.0.0.1:11434/api/generate')) : '';
  const cloudUrl = normalizeOllamaGenerateUrl(config.get('vulServer.ollamaCloudUrl', ''));
  const selectedUrl = useCloud ? cloudUrl : localUrl;
  const apiKey = String(config.get('vulServer.ollamaApiKey', '') || process.env.VUL_OLLAMA_API_KEY || '').trim();
  const localFallbacks = String(
    config.get('vulServer.ollamaLocalFallbacks', 'qwen2.5-coder:3b,mistral:7b-instruct,llama3.2:3b-instruct')
  );
  const cloudFallbacks = String(
    config.get('vulServer.ollamaCloudFallbacks', 'gpt-oss:120b-cloud,gpt-oss:20b-cloud')
  );
  const cweCatalogUrl = String(config.get('vulServer.cweCatalogUrl', 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')).trim();
  const cweCachePath = String(config.get('vulServer.cweCachePath', '')).trim();
  const cweRefreshHours = String(config.get('vulServer.cweRefreshHours', 168));

  return {
    VUL_RAG_ENABLED: config.get('vulServer.ragEnabled', true) ? '1' : '0',
    VUL_RAG_TOP_K: String(config.get('vulServer.ragTopK', 3)),
    VUL_RAG_MAX_LINES: String(config.get('vulServer.ragMaxLines', 5)),
    VUL_RAG_WINDOW: String(config.get('vulServer.ragWindow', 4)),
    VUL_RAG_CACHE: config.get('vulServer.ragCache', true) ? '1' : '0',
    VUL_STATIC_RULES_ENABLED: config.get('vulServer.staticRulesEnabled', true) ? '1' : '0',
    VUL_STATIC_MAX_FINDINGS: String(config.get('vulServer.staticMaxFindings', 6)),
    VUL_RAG_BUDGET_MS: String(config.get('vulServer.ragBudgetMs', 25000)),
    VUL_LLM_ENABLED: config.get('vulServer.llmEnabled', false) ? '1' : '0',
    VUL_LLM_PROVIDER: String(config.get('vulServer.llmProvider', 'ollama')),
    VUL_OLLAMA_URL: selectedUrl,
    VUL_OLLAMA_CLOUD_URL: cloudUrl,
    VUL_OLLAMA_API_KEY: apiKey,
    VUL_MODEL_USE_CLOUD: useCloud ? '1' : '0',
    VUL_OLLAMA_LOCAL_MODEL: ollamaModel,
    VUL_OLLAMA_CLOUD_MODEL: cloudModel,
    VUL_OLLAMA_MODEL_FALLBACKS: useCloud ? cloudFallbacks : localFallbacks,
    VUL_OLLAMA_MODEL: useCloud ? cloudModel : ollamaModel,
    VUL_LLM_TIMEOUT_MS: String(config.get('vulServer.llmTimeoutMs', 120000)),
    VUL_LLM_TEMPERATURE: String(config.get('vulServer.llmTemperature', 0.1)),
    VUL_CWE_CATALOG_URL: cweCatalogUrl,
    VUL_CWE_CACHE_PATH: cweCachePath,
    VUL_CWE_REFRESH_HOURS: cweRefreshHours,
  };
}

function hashText(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function buildAnalysisCacheKey(code, mode, ragEnv) {
  const payload = JSON.stringify({ code, mode, ragEnv });
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

function buildInferenceServerEnvKey(pythonPath, scriptPath, ragEnv) {
  return hashText(JSON.stringify({ pythonPath, scriptPath, ragEnv }));
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
  const ragEnv = buildRagEnv(config);
  const found = findLocalScriptPath(root, localScriptPath);
  const scriptPath = found.scriptPath;

  if (!scriptPath || !fs.existsSync(scriptPath)) {
    const tried = (found.tried || []).map((p) => `  - ${p}`).join('\n');
    throw new Error(`Local script not found. Configured value='${localScriptPath}'. Tried:\n${tried}`);
  }

  const serverCfg = getInferenceServerConfig(config);
  inferenceServerHost = serverCfg.host;
  inferenceServerPort = serverCfg.port;
  const envKey = buildInferenceServerEnvKey(pythonPath, scriptPath, ragEnv);

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
    env: { ...process.env, ...ragEnv },
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
  const ragEnv = buildRagEnv(config);
  const found = findLocalScriptPath(root, localScriptPath);
  const scriptPath = found.scriptPath || localScriptPath;
  const envKey = buildInferenceServerEnvKey(pythonPath, scriptPath, ragEnv);
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

function splitCsvList(rawValue) {
  return String(rawValue || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function tryParseJsonLoose(text) {
  const payload = String(text || '').trim();
  if (!payload) {
    return null;
  }

  try {
    return JSON.parse(payload);
  } catch (_) {
    const first = payload.indexOf('{');
    const last = payload.lastIndexOf('}');
    if (first >= 0 && last > first) {
      try {
        return JSON.parse(payload.slice(first, last + 1));
      } catch (_) {
        return null;
      }
    }
    return null;
  }
}

function getFixLlmConfig(config) {
  const useCloud = config.get('vulServer.useCloudModel', true) === true;
  // Keep both endpoints available regardless of preference so that a dead or
  // unreachable primary can fall through to the other one.
  const cloudUrl = normalizeOllamaGenerateUrl(config.get('vulServer.ollamaCloudUrl', '') || '');
  const localUrl = normalizeOllamaGenerateUrl(config.get('vulServer.ollamaUrl', 'http://127.0.0.1:11434/api/generate') || '');
  const cloudModel = String(config.get('vulServer.ollamaCloudModel', 'gpt-oss:120b-cloud') || '').trim();
  const cloudFallbacks = splitCsvList(config.get('vulServer.ollamaCloudFallbacks', 'gpt-oss:120b-cloud,gpt-oss:20b-cloud'));
  const localModel = String(config.get('vulServer.ollamaModel', 'qwen2.5-coder:3b') || '').trim();
  const localFallbacks = splitCsvList(config.get('vulServer.ollamaLocalFallbacks', 'qwen2.5-coder:3b,mistral:7b-instruct,llama3.2:3b-instruct'));
  const timeoutMs = Math.max(1000, Number(config.get('vulServer.llmTimeoutMs', 120000)) || 120000);
  const temperature = Number(config.get('vulServer.llmTemperature', 0.1)) || 0.1;
  const apiKey = String(config.get('vulServer.ollamaApiKey', '') || process.env.VUL_OLLAMA_API_KEY || '').trim();

  const cloudModels = [];
  for (const candidate of [cloudModel, ...cloudFallbacks]) {
    if (candidate && !cloudModels.includes(candidate)) {
      cloudModels.push(candidate);
    }
  }

  const localModels = [];
  for (const candidate of [localModel, ...localFallbacks]) {
    if (candidate && !localModels.includes(candidate)) {
      localModels.push(candidate);
    }
  }

  const endpoints = [];
  const seenUrls = new Set();
  const maybeAddEndpoint = (url, type, models) => {
    if (!url || seenUrls.has(url)) {
      return;
    }
    seenUrls.add(url);
    endpoints.push({
      url,
      type,
      models: Array.isArray(models) ? models : [],
    });
  };

  maybeAddEndpoint(cloudUrl, 'cloud', cloudModels);
  maybeAddEndpoint(localUrl, 'local', localModels);

  if (endpoints.length > 0) {
    for (const endpoint of endpoints) {
      if (endpoint.models.length === 0) {
        endpoint.models = endpoint.type === 'cloud' ? [...cloudModels, ...localModels] : [...localModels, ...cloudModels];
      }
    }
  }

  return {
    endpoints,
    apiKey,
    timeoutMs,
    temperature: Math.max(0.0, Math.min(1.0, temperature)),
  };
}

function makeHttpStatusError(status, body) {
  const err = new Error(`Ollama HTTP ${status}: ${String(body).slice(0, 300)}`);
  err.isHttpStatus = true;
  return err;
}

// Preferred transport. The extension host patches Node's http/https modules for
// proxy support, which injects JS callbacks into the response parser; when one
// of those throws, llhttp surfaces the opaque "Parse Error: JS Exception".
// fetch() uses a separate stack and is not affected.
async function httpPostJsonViaFetch(targetUrl, bodyObj, headers, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(headers || {}) },
      body: JSON.stringify(bodyObj),
      signal: controller.signal,
    });
    const text = await res.text();
    if (!res.ok) {
      throw makeHttpStatusError(res.status, text);
    }
    return text;
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw new Error(`Ollama request timeout after ${timeoutMs} ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function httpPostJsonViaNode(targetUrl, bodyObj, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    let urlObj;
    try {
      urlObj = new URL(targetUrl);
    } catch (err) {
      reject(new Error(`Invalid Ollama URL: ${targetUrl}`));
      return;
    }

    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;
    const payload = JSON.stringify(bodyObj);
    const req = client.request(
      {
        method: 'POST',
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: `${urlObj.pathname || '/'}${urlObj.search || ''}`,
        // Tolerate responses the strict parser rejects; this path is only
        // reached after the primary transport has already failed.
        insecureHTTPParser: true,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          ...(headers || {}),
        },
      },
      (res) => {
        let responseBody = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          responseBody += chunk;
        });
        res.on('end', () => {
          const status = Number(res.statusCode || 0);
          if (status < 200 || status >= 300) {
            reject(makeHttpStatusError(status, responseBody));
            return;
          }
          resolve(responseBody);
        });
      }
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Ollama request timeout after ${timeoutMs} ms`));
    });
    req.on('error', (err) => {
      const code = err && err.code ? ` (${err.code})` : '';
      const wrapped = new Error(`${String(err && err.message ? err.message : err)}${code}`);
      reject(wrapped);
    });
    req.write(payload);
    req.end();
  });
}

async function httpPostJson(targetUrl, bodyObj, headers, timeoutMs) {
  let primaryError = null;
  if (typeof fetch === 'function') {
    try {
      return await httpPostJsonViaFetch(targetUrl, bodyObj, headers, timeoutMs);
    } catch (err) {
      // A real HTTP status (404/410/401) is a definitive answer from the
      // server, not a transport problem, so do not retry it.
      if (err && err.isHttpStatus) {
        throw err;
      }
      primaryError = err;
    }
  }

  try {
    return await httpPostJsonViaNode(targetUrl, bodyObj, headers, timeoutMs);
  } catch (err) {
    if (primaryError && !(err && err.isHttpStatus)) {
      throw new Error(`${String(err && err.message ? err.message : err)} [fetch fallback also failed: ${String(primaryError.message || primaryError).slice(0, 120)}]`);
    }
    throw err;
  }
}

function normalizeFixPatches(rawPatches) {
  if (!Array.isArray(rawPatches)) {
    return [];
  }

  const normalized = [];
  for (const patch of rawPatches) {
    if (!patch || typeof patch !== 'object') {
      continue;
    }

    const startLine = Math.trunc(Number(patch.start_line));
    const endLine = Math.trunc(Number(patch.end_line));
    const replacement = String(patch.replacement || '');
    const originalSnippet = String(patch.original_snippet || '');
    if (!replacement.trim()) {
      continue;
    }

    // A patch is usable if it carries either a locatable anchor snippet or a
    // sane line range. Line numbers alone are unreliable: models routinely
    // number the code as they would format it, not as it sits on disk.
    const hasAnchor = originalSnippet.trim().length > 0;
    const hasLineRange = Number.isFinite(startLine) && Number.isFinite(endLine);
    if (!hasAnchor && !hasLineRange) {
      continue;
    }

    normalized.push({
      title: String(patch.title || 'Suggested fix').trim() || 'Suggested fix',
      start_line: hasLineRange ? startLine : null,
      end_line: hasLineRange ? endLine : null,
      original_snippet: originalSnippet,
      replacement,
      summary: String(patch.summary || '').trim(),
      safety_notes: String(patch.safety_notes || '').trim(),
      imports: Array.isArray(patch.imports) ? patch.imports : [],
      confidence: Number(patch.confidence),
    });
  }

  return normalized;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Locate an anchor snippet in the document, tolerating whitespace drift between
// what the model echoed back and what is actually on disk.
function findSnippetRanges(document, snippet) {
  const text = document.getText();
  const needle = String(snippet || '');
  if (!needle.trim()) {
    return [];
  }

  const ranges = [];
  let from = 0;
  while (from <= text.length) {
    const idx = text.indexOf(needle, from);
    if (idx < 0) break;
    ranges.push(new vscode.Range(document.positionAt(idx), document.positionAt(idx + needle.length)));
    from = idx + Math.max(1, needle.length);
  }
  if (ranges.length > 0) {
    return ranges;
  }

  // Whitespace-insensitive retry: collapse runs of whitespace into \s+ so that
  // reformatted or re-indented echoes still match the original source.
  const pattern = needle
    .trim()
    .split(/\s+/)
    .map(escapeRegExp)
    .join('\\s+');
  if (!pattern) {
    return [];
  }

  let re;
  try {
    re = new RegExp(pattern, 'g');
  } catch (_) {
    return [];
  }

  let match;
  while ((match = re.exec(text)) !== null) {
    ranges.push(new vscode.Range(document.positionAt(match.index), document.positionAt(match.index + match[0].length)));
    if (match.index === re.lastIndex) {
      re.lastIndex += 1;
    }
  }
  return ranges;
}

// Decide where a patch actually applies. Anchor text wins over line numbers;
// an out-of-range line span is rejected outright rather than clamped, because
// clamping silently rewrites the wrong region of the file.
function resolvePatchRange(document, patch, targetLine) {
  const anchors = findSnippetRanges(document, patch.original_snippet);
  if (anchors.length === 1) {
    return { range: anchors[0], strategy: 'anchor' };
  }
  if (anchors.length > 1) {
    // Ambiguous anchor: prefer the occurrence closest to the reported finding.
    const pivot = Math.max(0, Math.trunc(Number(targetLine) || 1) - 1);
    let best = anchors[0];
    let bestDistance = Math.abs(anchors[0].start.line - pivot);
    for (const candidate of anchors.slice(1)) {
      const distance = Math.abs(candidate.start.line - pivot);
      if (distance < bestDistance) {
        best = candidate;
        bestDistance = distance;
      }
    }
    return { range: best, strategy: 'anchor-nearest' };
  }

  const startLine = Math.trunc(Number(patch.start_line));
  const endLine = Math.trunc(Number(patch.end_line));
  if (!Number.isFinite(startLine) || !Number.isFinite(endLine)) {
    return null;
  }
  if (startLine < 1 || endLine < startLine || endLine > document.lineCount) {
    return null;
  }

  const endText = document.lineAt(endLine - 1).text;
  return {
    range: new vscode.Range(new vscode.Position(startLine - 1, 0), new vscode.Position(endLine - 1, endText.length)),
    strategy: 'line-range',
  };
}

function buildFixPrompt(payload) {
  return [
    'You are a secure code remediation assistant.',
    'Return STRICT JSON ONLY with object keys: patches, explanation.',
    'patches must be an array (max 3) of objects with keys:',
    'title, original_snippet, start_line, end_line, replacement, summary, safety_notes, imports, confidence.',
    'Rules:',
    '- original_snippet is REQUIRED: copy the exact substring of the original file that must be',
    '  replaced, character for character, including its original spacing. Do not reformat it and',
    '  do not paraphrase it. It is used to locate the edit, so it must appear verbatim in the file.',
    '- Keep original_snippet as short as possible while still being unique in the file.',
    '- start_line/end_line are 1-based line numbers in the ORIGINAL file as it is stored on disk.',
    '  The file may keep an entire function on ONE physical line; in that case both are 1.',
    '  Never invent line numbers from your own formatting of the code.',
    '- replacement is the exact code that must take the place of original_snippet.',
    '- Keep edits minimal and compile-safe.',
    '- Do not include markdown or backticks.',
    '- Ignore any <S2SV_StartBug> / <S2SV_EndBug> dataset markers: they are annotations, not code,',
    '  and must be preserved verbatim if they fall inside the text you replace.',
    '- If the stated CWE does not match the code, fix the real vulnerability you can see on the',
    '  target line instead, and say so in explanation. Return an empty patches array only when the',
    '  code genuinely has no fixable defect.',
    '',
    `Language: ${payload.languageId}`,
    `Target line: ${payload.targetLine}`,
    `Finding title: ${payload.findingTitle}`,
    `CWE: ${payload.findingCwe}`,
    `Finding explanation: ${payload.findingExplanation}`,
    `Selected suggestion summary: ${payload.suggestionSummary}`,
    `Selected patch hint: ${payload.suggestionPatchHint}`,
    '',
    'Context window (with line numbers):',
    payload.contextWindow,
    '',
    'Full file content (may be truncated):',
    payload.fileContent,
  ].join('\n');
}

function buildNumberedContextWindow(document, centerLine, radius) {
  const start = Math.max(1, centerLine - radius);
  const end = Math.min(document.lineCount, centerLine + radius);
  const parts = [];
  for (let ln = start; ln <= end; ln += 1) {
    parts.push(`${ln}: ${document.lineAt(ln - 1).text}`);
  }
  return parts.join('\n');
}

async function generateFixPatchesWithOllama(document, finding, suggestion) {
  const config = vscode.workspace.getConfiguration();
  const llmCfg = getFixLlmConfig(config);
  if (!Array.isArray(llmCfg.endpoints) || llmCfg.endpoints.length === 0) {
    throw new Error('No Ollama endpoint configured for fix generation.');
  }

  const lineNo = Math.max(1, Math.trunc(Number(finding && finding.line) || 1));
  const rawContent = document.getText();
  const maxChars = 16000;
  const fileContent = rawContent.length > maxChars
    ? `${rawContent.slice(0, maxChars)}\n/* ... file truncated for fix generation ... */`
    : rawContent;
  const payload = {
    languageId: document.languageId || 'unknown',
    targetLine: lineNo,
    findingTitle: finding && finding.title ? String(finding.title) : '',
    findingCwe: finding && finding.cwe ? String(finding.cwe) : 'unknown',
    findingExplanation: finding && finding.explanation ? String(finding.explanation) : '',
    suggestionSummary: suggestion && suggestion.summary ? String(suggestion.summary) : '',
    suggestionPatchHint: suggestion && suggestion.patch_hint ? String(suggestion.patch_hint) : '',
    contextWindow: buildNumberedContextWindow(document, lineNo, 6),
    fileContent,
  };

  const basePrompt = buildFixPrompt(payload);
  const retryPrompt = [
    basePrompt,
    '',
    'PREVIOUS ATTEMPT FAILED. It returned no patch that could be located in the file.',
    'Try again and obey these constraints exactly:',
    '- You MUST return at least one patch unless the code is genuinely not fixable.',
    '- original_snippet MUST be copied verbatim from the file content shown above. Before',
    '  answering, re-read the file content and confirm your original_snippet appears in it',
    '  character for character.',
    '- Prefer a SHORT original_snippet (a single statement or expression) over a long one.',
    '- If the stated CWE looks wrong for this code, fix the actual defect on the target line.',
  ].join('\n');

  const headers = {};
  if (llmCfg.apiKey) {
    headers.Authorization = `Bearer ${llmCfg.apiKey}`;
  }

  const attempts = [];
  const runPass = async (prompt, passLabel) => {
    for (const endpoint of llmCfg.endpoints) {
      const endpointUrl = endpoint.url;
      const models = Array.isArray(endpoint.models) ? endpoint.models : [];
      if (models.length === 0) {
        continue;
      }

      for (const modelName of models) {
        const requestBody = {
          model: modelName,
          prompt,
          stream: false,
          format: 'json',
          // Ollama only honours sampling parameters nested under `options`.
          options: { temperature: llmCfg.temperature },
        };

        const label = `${passLabel}/${endpoint.type}/${modelName}`;
        try {
          const responseText = await httpPostJson(endpointUrl, requestBody, headers, llmCfg.timeoutMs);
          const topLevel = tryParseJsonLoose(responseText);
          if (!topLevel || typeof topLevel !== 'object') {
            attempts.push(`${label}: provider_response_not_json: ${responseText.slice(0, 160)}`);
            continue;
          }

          if (topLevel.error) {
            attempts.push(`${label}: ${String(topLevel.error).slice(0, 160)}`);
            continue;
          }

          const modelResponse = tryParseJsonLoose(String(topLevel.response || ''));
          if (!modelResponse || typeof modelResponse !== 'object') {
            attempts.push(`${label}: model_response_not_structured_json: ${String(topLevel.response || '').slice(0, 160)}`);
            continue;
          }

          const explanation = String(modelResponse.explanation || '');
          const patches = normalizeFixPatches(modelResponse.patches);
          if (patches.length === 0) {
            attempts.push(`${label}: model returned no patches: ${explanation.slice(0, 160)}`);
            continue;
          }

          // Keep only patches we can actually place in this document. An
          // unplaceable patch is worse than none: clamping it would rewrite
          // the wrong region.
          const placed = [];
          for (const patch of patches) {
            const resolved = resolvePatchRange(document, patch, lineNo);
            if (resolved) {
              placed.push({ ...patch, range: resolved.range, strategy: resolved.strategy });
            }
          }

          if (placed.length === 0) {
            attempts.push(`${label}: ${patches.length} patch(es) could not be located in the file`);
            continue;
          }

          return {
            patches: placed,
            modelName,
            explanation,
            usingCloud: endpoint.type === 'cloud',
          };
        } catch (err) {
          attempts.push(`${label}: ${String(err && err.message ? err.message : err).slice(0, 160)}`);
        }
      }
    }
    return null;
  };

  const first = await runPass(basePrompt, 'pass1');
  if (first) {
    return first;
  }

  const second = await runPass(retryPrompt, 'pass2');
  if (second) {
    return second;
  }

  const detail = attempts.length > 0 ? attempts.join(' | ') : 'no_successful_model_response';
  const failure = new Error(`Fix generation failed: ${detail}`);
  failure.attempts = attempts;
  throw failure;
}

function computePythonImportInsertionLine(document) {
  let idx = 0;
  if (document.lineCount > 0 && document.lineAt(0).text.startsWith('#!')) {
    idx = 1;
  }

  let lastImport = -1;
  for (let i = idx; i < document.lineCount; i += 1) {
    const text = document.lineAt(i).text.trim();
    if (!text) {
      if (lastImport >= 0) {
        break;
      }
      continue;
    }
    if (/^(from\s+\S+\s+import\s+.+|import\s+.+)$/.test(text)) {
      lastImport = i;
      continue;
    }
    if (lastImport >= 0) {
      break;
    }
  }

  if (lastImport >= 0) {
    return lastImport + 1;
  }
  return idx;
}

function applyRequiredImports(edit, document, imports) {
  if (!document || !Array.isArray(imports) || imports.length === 0) {
    return;
  }

  if (document.languageId !== 'python') {
    return;
  }

  const existingText = document.getText();
  const unique = Array.from(new Set(imports.map((x) => String(x).trim()).filter(Boolean)));
  const missing = unique.filter((stmt) => !existingText.includes(stmt));
  if (missing.length === 0) {
    return;
  }

  const insertLine = computePythonImportInsertionLine(document);
  const importBlock = `${missing.join('\n')}\n`;
  edit.insert(document.uri, new vscode.Position(insertLine, 0), importBlock);
}

function truncateForPreview(text, maxChars) {
  const value = String(text || '');
  return value.length > maxChars ? `${value.slice(0, maxChars)}…` : value;
}

function describePatchLocation(patch) {
  if (!patch || !patch.range) {
    return 'unknown location';
  }
  const startLine = patch.range.start.line + 1;
  const endLine = patch.range.end.line + 1;
  const where = startLine === endLine
    ? `line ${startLine}, cols ${patch.range.start.character + 1}-${patch.range.end.character + 1}`
    : `lines ${startLine}-${endLine}`;
  return patch.strategy === 'line-range' ? where : `${where} (matched text)`;
}

// Guidance text comes from an LLM and is frequently multi-line and wrapped in
// markdown fences. Every line must be commented out, or inserting it breaks the
// file it is meant to annotate.
function buildGuidanceComment(indent, prefix, parts) {
  const lines = [`SECURITY (${parts.cwe}): ${parts.summary || 'Review this line.'}`];

  const appendBlock = (label, body) => {
    if (!body) {
      return;
    }
    const cleaned = String(body)
      .split('\n')
      .map((line) => line.replace(/^\s*```[a-zA-Z0-9+-]*\s*$/, '').trimEnd())
      .filter((line, idx, arr) => line.trim() !== '' || (idx > 0 && idx < arr.length - 1));
    if (cleaned.length === 0) {
      return;
    }
    lines.push(`${label}: ${cleaned[0].trim()}`);
    for (const line of cleaned.slice(1)) {
      lines.push(`  ${line.trim()}`);
    }
  };

  appendBlock('Suggested change', parts.hint);
  appendBlock('Safety', parts.notes);

  return lines
    .filter((line) => line.trim() !== '')
    .map((line) => `${indent}${prefix} ${line}`.trimEnd())
    .join('\n');
}

function getLineCommentPrefix(languageId) {
  const hashLanguages = new Set(['python', 'shellscript', 'ruby', 'yaml', 'perl', 'makefile']);
  if (hashLanguages.has(String(languageId || ''))) {
    return '#';
  }
  return '//';
}

// Last-resort path when the model cannot produce a placeable patch: surface the
// backend's concrete guidance so the run still ends with something actionable
// instead of a dead end.
async function offerStaticFixHint(editor, finding, suggestion, failureMessage) {
  const summary = suggestion && suggestion.summary ? String(suggestion.summary).trim() : '';
  const hint = suggestion && suggestion.patch_hint ? String(suggestion.patch_hint).trim() : '';
  const notes = suggestion && suggestion.safety_notes ? String(suggestion.safety_notes).trim() : '';

  if (!summary && !hint) {
    vscode.window.showErrorMessage(`Failed to generate fix: ${truncateForPreview(failureMessage, 300)}`);
    return;
  }

  const detailLines = [summary, hint ? `Suggested change: ${hint}` : '', notes ? `Safety: ${notes}` : '']
    .filter(Boolean)
    .join('\n');

  const choice = await vscode.window.showWarningMessage(
    `The model could not produce an applicable patch, so no code was changed.\n\nBackend guidance for ${finding && finding.cwe ? finding.cwe : 'this finding'}:\n${detailLines}`,
    { modal: true },
    'Insert as Comment',
    'Copy Guidance'
  );

  if (choice === 'Copy Guidance') {
    await vscode.env.clipboard.writeText(hint || summary);
    vscode.window.showInformationMessage('Fix guidance copied to clipboard.');
    return;
  }

  if (choice !== 'Insert as Comment') {
    return;
  }

  const lineIndex = Math.max(0, Math.min(editor.document.lineCount - 1, Math.trunc(Number(finding && finding.line) || 1) - 1));
  const prefix = getLineCommentPrefix(editor.document.languageId);
  const indent = editor.document.lineAt(lineIndex).text.match(/^\s*/)[0];
  const commentBody = buildGuidanceComment(indent, prefix, {
    cwe: finding && finding.cwe ? String(finding.cwe) : 'review',
    summary,
    hint,
    notes,
  });

  const edit = new vscode.WorkspaceEdit();
  edit.insert(editor.document.uri, new vscode.Position(lineIndex, 0), `${commentBody}\n`);
  const ok = await vscode.workspace.applyEdit(edit);
  vscode.window.showInformationMessage(
    ok ? 'Inserted fix guidance as a comment for manual review.' : 'Could not insert the guidance comment.'
  );
}

async function applySuggestedFix() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor found.');
    return;
  }

  const stored = getStoredAnalysis(editor);
  if (!stored || !Array.isArray(stored.findings) || stored.findings.length === 0) {
    vscode.window.showWarningMessage('No findings found for this file. Run vulnerability analysis first.');
    return;
  }

  const findings = stored.findings
    .filter((item) => item && Number.isFinite(Number(item.line)))
    // Clamp rather than discard: the backend numbers lines against its own view
    // of the code, which can overshoot files that keep a whole function on one
    // physical line. The patch itself is located by anchor text, so an
    // optimistic line number is only a hint.
    .map((item) => ({
      ...item,
      line: Math.max(1, Math.min(editor.document.lineCount, Math.trunc(Number(item.line)))),
    }))
    .sort((a, b) => {
      const confA = Number(a && a.confidence && a.confidence.final);
      const confB = Number(b && b.confidence && b.confidence.final);
      if (Number.isFinite(confA) && Number.isFinite(confB) && confA !== confB) {
        return confB - confA;
      }
      return a.line - b.line;
    });

  if (findings.length === 0) {
    vscode.window.showWarningMessage('No fixable findings are available for this file.');
    return;
  }

  const findingPick = await vscode.window.showQuickPick(
    findings.map((finding) => {
      const cwe = finding.cwe ? String(finding.cwe) : 'unknown';
      const title = finding.title ? String(finding.title) : 'Potential vulnerability';
      const explanation = finding.explanation ? String(finding.explanation) : '';
      return {
        label: `Line ${finding.line}: ${title}`,
        description: cwe,
        detail: explanation,
        finding,
      };
    }),
    {
      title: 'Choose Vulnerability to Fix',
      placeHolder: 'Select a finding',
    }
  );

  if (!findingPick) {
    return;
  }

  const chosenFinding = findingPick.finding;
  const suggestions = Array.isArray(chosenFinding.fix_suggestions) && chosenFinding.fix_suggestions.length > 0
    ? chosenFinding.fix_suggestions
    : [{ summary: 'Apply manual security hardening', patch_hint: '', safety_notes: '' }];

  const suggestionPick = await vscode.window.showQuickPick(
    suggestions.map((item, idx) => {
      const summary = item && item.summary ? String(item.summary) : `Suggestion ${idx + 1}`;
      const hint = item && item.patch_hint ? String(item.patch_hint) : '';
      const notes = item && item.safety_notes ? String(item.safety_notes) : '';
      return {
        label: `${idx + 1}. ${summary}`,
        description: hint,
        detail: notes,
        suggestion: item,
      };
    }),
    {
      title: 'Choose Fix Strategy',
      placeHolder: 'Select a suggested fix',
    }
  );

  if (!suggestionPick) {
    return;
  }

  const lineNo = Math.trunc(Number(chosenFinding.line)) - 1;
  if (lineNo < 0 || lineNo >= editor.document.lineCount) {
    vscode.window.showErrorMessage('Selected finding line is out of range in current document.');
    return;
  }

  let fixGeneration;
  try {
    fixGeneration = await generateFixPatchesWithOllama(editor.document, chosenFinding, suggestionPick.suggestion);
  } catch (err) {
    const msg = String(err && err.message ? err.message : err);
    output.appendLine('--- Vul Extension Fix Generation Error ---');
    output.appendLine(msg);
    output.appendLine('--- End Fix Error ---\n');
    output.show(true);
    await offerStaticFixHint(editor, chosenFinding, suggestionPick.suggestion, msg);
    return;
  }

  const patchChoice = await vscode.window.showQuickPick(
    fixGeneration.patches.map((patch, idx) => ({
      label: `${idx + 1}. ${patch.title}`,
      description: describePatchLocation(patch),
      detail: patch.summary || patch.safety_notes || '',
      patch,
    })),
    {
      title: 'Choose Model-Generated Patch',
      placeHolder: 'Select a patch candidate',
    }
  );

  if (!patchChoice) {
    return;
  }

  const selectedPatch = patchChoice.patch;
  // The range was resolved against this document during generation (anchor text
  // preferred over model-reported line numbers), so apply it as-is.
  const targetRange = selectedPatch.range;
  const preview = `${selectedPatch.replacement}`.split('\n').slice(0, 12).join('\n');
  const currentText = editor.document.getText(targetRange);
  const currentPreview = currentText.split('\n').slice(0, 6).join('\n');
  const approval = await vscode.window.showWarningMessage(
    `Apply model-generated fix at ${describePatchLocation(selectedPatch)}?\n\nReplacing:\n${truncateForPreview(currentPreview, 600)}\n\nWith:\n${truncateForPreview(preview, 600)}`,
    { modal: true },
    'Apply Fix',
    'Cancel'
  );
  if (approval !== 'Apply Fix') {
    vscode.window.showInformationMessage('Fix application cancelled by user.');
    return;
  }

  const edit = new vscode.WorkspaceEdit();
  edit.replace(editor.document.uri, targetRange, String(selectedPatch.replacement || '').trimEnd());

  applyRequiredImports(edit, editor.document, selectedPatch.imports || []);

  const ok = await vscode.workspace.applyEdit(edit);
  if (!ok) {
    vscode.window.showErrorMessage('Failed to apply the selected fix.');
    return;
  }

  clearVulnerabilityHighlights(editor);
  lastAnalysisByUri.delete(getAnalysisKey(editor.document));
  updateStatusBarButton();

  const rerun = await vscode.window.showInformationMessage(
    `Applied fix using ${fixGeneration.usingCloud ? 'Ollama Cloud' : 'Ollama endpoint'} model ${fixGeneration.modelName}.`,
    'Re-run Analysis'
  );
  if (rerun === 'Re-run Analysis') {
    await vscode.commands.executeCommand('vulExtension.analyzeActiveEditor');
  }
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
  const ragEnv = buildRagEnv(config);

  const remoteEnvPrefix = buildRemoteEnvPrefix(ragEnv);
  const remoteCmd = `${remoteEnvPrefix} ${remotePython} ${remoteScript} --stdin --compact-json`;
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
        const ragEnv = buildRagEnv(config);
        const cacheKey = buildAnalysisCacheKey(code, mode, ragEnv);
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
        const ragMeta = (res.json && typeof res.json.rag_metadata === 'object') ? res.json.rag_metadata : {};
        const detectionMethod = res.json && res.json.detection_method ? String(res.json.detection_method) : 'unknown';

        output.appendLine(`mode=${res.mode} | time=${elapsedMs}ms | prob=${p} | vulnerable_lines=${lineCount} | findings=${findings.length}`);
        output.appendLine(`detection_method=${detectionMethod}`);
        if (ragMeta && Object.keys(ragMeta).length > 0) {
          output.appendLine(`rag_mode=${ragMeta.mode || 'unknown'} | llm_used=${ragMeta.llm_used || 0} | retrieval_hits=${ragMeta.retrieval_hits || 0} | cache_hits=${ragMeta.cache_hits || 0} | rag_elapsed_ms=${ragMeta.elapsed_ms || 0}`);
        }
        if (findings.length > 0) {
          output.appendLine('Top findings:');
          for (const finding of findings.slice(0, 3)) {
            const lineNo = Number(finding && finding.line);
            const lineText = Number.isFinite(lineNo) ? `line ${lineNo}` : 'line n/a';
            const cwe = finding && finding.cwe ? String(finding.cwe) : 'unknown';
            const why = finding && finding.explanation ? String(finding.explanation) : 'n/a';
            output.appendLine(`  - ${lineText} [${cwe}] ${why}`);
            if (Array.isArray(finding && finding.fix_suggestions) && finding.fix_suggestions.length > 0) {
              const primaryFix = finding.fix_suggestions[0] && finding.fix_suggestions[0].summary
                ? String(finding.fix_suggestions[0].summary)
                : '';
              if (primaryFix) {
                output.appendLine(`    fix: ${primaryFix}`);
              }
            }
          }
        }
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

        const completionMessage = `Vul analysis complete: prob=${p}, lines=${lineCount}, findings=${findings.length}, time=${elapsedMs}ms`;
        if (findings.length > 0) {
          const action = await vscode.window.showInformationMessage(
            completionMessage,
            'Choose Fix'
          );
          if (action === 'Choose Fix') {
            await vscode.commands.executeCommand('vulExtension.applySuggestedFix');
          }
        } else {
          vscode.window.showInformationMessage(completionMessage);
        }
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
  const applyFix = vscode.commands.registerCommand('vulExtension.applySuggestedFix', () => applySuggestedFix());
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
    applyFix,
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
