import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:5000";

const sampleManifest = JSON.stringify({
  name: "demo-project",
  dependencies: {
    "flask": "3.0.0",
    "requests": "2.31.0",
    "axios": "1.6.0",
    "lodash": "4.17.20"
  },
  devDependencies: {
    "vite": "5.0.0"
  }
}, null, 2);

function App() {
  const [fileName, setFileName] = useState("package.json");
  const [content, setContent] = useState(sampleManifest);
  const [projectName, setProjectName] = useState("demo-project");
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [view, setView] = useState("dashboard");
  const [apiOnline, setApiOnline] = useState(false);

  async function loadHistory() {
    try {
      const response = await fetch(`${API}/api/history`);
      if (!response.ok) throw new Error("History unavailable");
      setHistory(await response.json());
    } catch {
      setHistory([]);
    }
  }

  useEffect(() => {
    fetch(`${API}/api/health`)
      .then(r => {
        if (!r.ok) throw new Error("Offline");
        return r.json();
      })
      .then(() => setApiOnline(true))
      .catch(() => setApiOnline(false));

    loadHistory();
  }, []);

  async function scanProject() {
    setLoading(true);
    setError("");
    setReport(null);

    try {
      const response = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: fileName,
          content,
          project_name: projectName
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Scan failed");
      }

      setReport(data);
      setView("results");
      await loadHistory();
    } catch (err) {
      setError(
        err.message.includes("fetch")
          ? "Backend not connected. Start the Flask server on port 5000."
          : err.message
      );
    } finally {
      setLoading(false);
    }
  }

  async function openHistory(id) {
    setError("");

    try {
      const response = await fetch(`${API}/api/history/${id}`);
      const data = await response.json();

      if (!response.ok) throw new Error(data.error || "Could not open report");

      setReport(data);
      setView("results");
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!["package.json", "requirements.txt"].includes(file.name)) {
      setError("Choose package.json or requirements.txt.");
      return;
    }

    try {
      const text = await file.text();
      setContent(text);
      setFileName(file.name);
      setProjectName(file.name === "package.json" ? "My Project" : "Python Project");
      setReport(null);
      setError("");
      setView("dashboard");
    } catch {
      setError("Could not read the selected file.");
    }
  }

  const score = report?.score ?? 0;
  const scoreLabel = score >= 80 ? "Healthy" : score >= 60 ? "Moderate Risk" : "High Risk";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">R</div>
          <div>
            <strong>ROSPL</strong>
            <span>Dependency Intelligence</span>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <button className={`nav-item ${view === "dashboard" ? "active" : ""}`}
          onClick={() => setView("dashboard")}>
          <span>▦</span> Overview
        </button>
        <button className={`nav-item ${view === "results" ? "active" : ""}`}
          onClick={() => report ? setView("results") : setError("Run a scan to view results.")}>
          <span>⌕</span> Scan Results
        </button>
        <button className={`nav-item ${view === "history" ? "active" : ""}`}
          onClick={() => { setView("history"); loadHistory(); }}>
          <span>◷</span> Scan History
        </button>

        <div className="sidebar-bottom">
          <div className="status-card">
            <span className={`status-dot ${apiOnline ? "" : "offline"}`} />
            <div>
              <strong>API Status</strong>
              <p>{apiOnline ? "Backend connected" : "Backend offline"}</p>
            </div>
          </div>
          <p className="sidebar-footer">Open Source Software Lab<br />Dependency Health Analyzer</p>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <span className="breadcrumb">Workspace / </span>
            <strong>{view === "history" ? "Scan History" : view === "results" ? "Scan Report" : "Overview"}</strong>
          </div>
          <div className="top-right">
            <span className={`connection-pill ${apiOnline ? "online" : "offline-pill"}`}>
              <span className="status-dot" /> {apiOnline ? "System Online" : "System Offline"}
            </span>
            <div className="avatar">SP</div>
          </div>
        </header>

        <div className="page-content">
          {error && (
            <div className="error-banner">
              <span>{error}</span>
              <button onClick={() => setError("")}>×</button>
            </div>
          )}

          {view === "dashboard" && (
            <>
              <section className="welcome-row">
                <div>
                  <p className="eyebrow">DEPENDENCY SECURITY WORKSPACE</p>
                  <h1>Dependency Health Analyzer</h1>
                  <p className="subtitle">Identify vulnerable packages and assess your open-source dependency risk.</p>
                </div>
                <div className="date-chip">LIVE ANALYSIS</div>
              </section>

              <section className="stats-grid">
                <Stat title="Total Scans" value={history.length} note="Saved scan reports" symbol="↗" />
                <Stat title="Dependencies Checked" value={history.reduce((n, h) => n + (h.dependency_count || 0), 0)} note="Across saved scans" symbol="◇" />
                <Stat title="Vulnerable Packages" value={history.reduce((n, h) => n + (h.vulnerable_count || 0), 0)} note="Across saved scans" symbol="!" />
                <Stat title="Latest Health Score" value={history.length ? `${history[0].score}/100` : "—"} note="Heuristic score" symbol="✓" />
              </section>

              <section className="scan-layout">
                <div className="panel scan-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>New Dependency Scan</h2>
                      <p>Upload a manifest or use the sample project.</p>
                    </div>
                    <span className="step-number">01</span>
                  </div>

                  <label className="field-label">PROJECT NAME</label>
                  <input className="text-input" value={projectName}
                    onChange={e => setProjectName(e.target.value)} placeholder="Enter project name" />

                  <label className="field-label">DEPENDENCY MANIFEST</label>
                  <div className="upload-box">
                    <div className="upload-icon">↑</div>
                    <strong>Choose a manifest file</strong>
                    <p>Supported formats: package.json, requirements.txt</p>
                    <label className="upload-button">
                      Browse Files
                      <input type="file" accept=".json,.txt" onChange={handleFile} />
                    </label>
                    <span className="selected-file">Selected: {fileName}</span>
                  </div>

                  <label className="field-label">MANIFEST PREVIEW</label>
                  <textarea className="manifest-editor" value={content}
                    onChange={e => setContent(e.target.value)} spellCheck="false" />

                  <div className="scan-actions">
                    <button className="secondary-button" onClick={() => {
                      setContent(sampleManifest);
                      setFileName("package.json");
                      setProjectName("demo-project");
                      setError("");
                    }}>Load Sample</button>
                    <button className="primary-button" onClick={scanProject} disabled={loading || !apiOnline}>
                      {loading ? <><span className="spinner" /> Scanning...</> : "Run Security Scan →"}
                    </button>
                  </div>
                  <p className="helper-text">Exact versions are checked against the OSV vulnerability database when available.</p>
                </div>

                <div className="right-column">
                  <div className="panel info-panel">
                    <p className="eyebrow">HOW IT WORKS</p>
                    <h2>From manifest to insights</h2>
                    <div className="process-step">
                      <div className="process-icon">01</div>
                      <div><strong>Parse Dependencies</strong><p>Extract packages and declared versions.</p></div>
                    </div>
                    <div className="process-step">
                      <div className="process-icon">02</div>
                      <div><strong>Check Vulnerabilities</strong><p>Query OSV for known advisory records.</p></div>
                    </div>
                    <div className="process-step">
                      <div className="process-icon">03</div>
                      <div><strong>Assess Risk</strong><p>Generate a heuristic score and recommendations.</p></div>
                    </div>
                  </div>

                  <div className="notice-panel">
                    <span className="notice-icon">i</span>
                    <div><strong>Analysis note</strong><p>The score is a heuristic indicator, not a formal security certification. Packages that cannot be verified may need manual review.</p></div>
                  </div>
                </div>
              </section>

              <section className="panel recent-panel">
                <div className="section-heading">
                  <div><h2>Recent Scans</h2><p>Your latest saved dependency reports</p></div>
                  <button className="text-button" onClick={() => { setView("history"); loadHistory(); }}>View all →</button>
                </div>
                <HistoryTable items={history.slice(0, 5)} onOpen={openHistory} />
              </section>
            </>
          )}

          {view === "results" && report && (
            <>
              <section className="welcome-row">
                <div>
                  <p className="eyebrow">ANALYSIS REPORT</p>
                  <h1>{report.project_name}</h1>
                  <p className="subtitle">Scanned {new Date(report.scanned_at).toLocaleString()}</p>
                </div>
                <button className="secondary-button" onClick={() => setView("dashboard")}>← Back to Dashboard</button>
              </section>

              <section className="result-hero panel">
                <div className="score-ring" style={{ "--score": `${score * 3.6}deg` }}>
                  <div><strong>{score}</strong><span>/ 100</span></div>
                </div>
                <div className="score-copy">
                  <span className={`risk-badge ${score >= 80 ? "good" : score >= 60 ? "medium" : "bad"}`}>{scoreLabel}</span>
                  <h2>Dependency Health Score</h2>
                  <p>{report.score_description}</p>
                  <small>{report.osv_checked_count} checked · {report.unverified_count} unverified</small>
                </div>
              </section>

              <section className="stats-grid result-stats">
                <Stat title="Total Dependencies" value={report.dependency_count} note="Parsed packages" symbol="◇" />
                <Stat title="Vulnerable Packages" value={report.vulnerable_packages} note="Packages with OSV records" symbol="!" />
                <Stat title="Vulnerability Records" value={report.vulnerability_count} note="Known advisory records" symbol="⌕" />
                <Stat title="Needs Review" value={report.unverified_count} note="Could not be verified" symbol="◷" />
              </section>

              <section className="panel table-panel">
                <div className="section-heading"><div><h2>Dependency Details</h2><p>Package-level security findings</p></div></div>
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>PACKAGE</th><th>VERSION</th><th>STATUS</th><th>FINDINGS</th></tr></thead>
                    <tbody>
                      {report.dependencies?.map((dep, i) => (
                        <tr key={`${dep.name}-${i}`}>
                          <td><strong>{dep.name}</strong><small>{dep.ecosystem}</small></td>
                          <td><code>{dep.version}</code></td>
                          <td><span className={`status-badge ${dep.status === "Vulnerable" ? "bad" : dep.status === "Needs review" ? "medium" : "good"}`}>{dep.status}</span></td>
                          <td>
                            {dep.vulnerabilities?.length ? dep.vulnerabilities.map(v => (
                              <div className="finding" key={v.id}>
                                <strong>{v.id}</strong><p>{v.summary}</p>
                                {v.references?.map(url => <a key={url} href={url} target="_blank" rel="noreferrer">Advisory ↗</a>)}
                              </div>
                            )) : <span className="muted">{dep.flags?.join("; ") || "No OSV findings"}</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="panel recommendations-panel">
                <div className="section-heading"><div><h2>Recommendations</h2><p>Suggested follow-up actions</p></div></div>
                {report.recommendations?.length ? report.recommendations.map((r, i) => (
                  <div className="recommendation" key={`${r.package}-${i}`}>
                    <span className={`priority ${r.priority.toLowerCase()}`}>{r.priority}</span>
                    <div><strong>{r.package}</strong><p>{r.action}</p></div>
                  </div>
                )) : <p className="muted">No additional recommendations generated for this scan.</p>}
              </section>
            </>
          )}

          {view === "history" && (
            <>
              <section className="welcome-row">
                <div><p className="eyebrow">AUDIT TRAIL</p><h1>Scan History</h1><p className="subtitle">Review previously saved dependency analysis reports.</p></div>
                <button className="primary-button" onClick={() => setView("dashboard")}>+ New Scan</button>
              </section>
              <section className="panel table-panel">
                <div className="section-heading"><div><h2>All Scans</h2><p>{history.length} saved reports</p></div><button className="secondary-button" onClick={loadHistory}>Refresh</button></div>
                <HistoryTable items={history} onOpen={openHistory} />
              </section>
            </>
          )}

          <footer className="page-footer">ROSPL · Open-Source Dependency Health & Risk Analyzer <span>Built for software supply-chain awareness</span></footer>
        </div>
      </main>
    </div>
  );
}

function Stat({ title, value, note, symbol }) {
  return <div className="panel stat-card">
    <div className="stat-top"><span>{title}</span><span className="stat-symbol">{symbol}</span></div>
    <strong className="stat-value">{value}</strong>
    <span className="stat-note">{note}</span>
  </div>;
}

function HistoryTable({ items, onOpen }) {
  if (!items.length) return <div className="empty-state">No scans saved yet. Run your first dependency scan to see results here.</div>;

  return <div className="table-wrap">
    <table>
      <thead><tr><th>PROJECT</th><th>DATE</th><th>DEPENDENCIES</th><th>HEALTH SCORE</th><th>VULNERABLE</th><th></th></tr></thead>
      <tbody>{items.map(item => (
        <tr key={item.id}>
          <td><strong>{item.project_name}</strong><small>Scan #{item.id}</small></td>
          <td>{new Date(item.scanned_at).toLocaleString()}</td>
          <td>{item.dependency_count}</td>
          <td><span className={`score-pill ${item.score >= 80 ? "good" : item.score >= 60 ? "medium" : "bad"}`}>{item.score}/100</span></td>
          <td>{item.vulnerable_count}</td>
          <td><button className="text-button" onClick={() => onOpen(item.id)}>View report →</button></td>
        </tr>
      ))}</tbody>
    </table>
  </div>;
}

export default App;

