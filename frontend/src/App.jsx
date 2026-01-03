import { useState } from "react";

function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // 🔹 SCAN FUNCTION
  const handleScan = async () => {
    if (!file) {
      alert("Please select a file");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    setLoading(true);
    setResult(null);
    setError("");

    try {
      const response = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Scan failed");
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError("Unable to scan file. Is backend running?");
    } finally {
      setLoading(false);
    }
  };

  // 🔹 PDF DOWNLOAD FUNCTION (MUST BE OUTSIDE handleScan)
  const handleDownloadReport = async () => {
    if (!file) {
      alert("Please select a file first");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("http://127.0.0.1:8000/report", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Report generation failed");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = "ShieldWatch_Report.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();

      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert("Failed to download report");
    }
  };

  return (
    <div style={{ padding: "40px", fontFamily: "Arial" }}>
      <h1>ShieldWatch Malware Scanner</h1>

      <input
        type="file"
        onChange={(e) => setFile(e.target.files[0])}
      />

      <br /><br />

      <button onClick={handleScan} disabled={loading}>
        {loading ? "Scanning..." : "Scan File"}
      </button>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {result && (
        <div style={{ marginTop: "30px" }}>
          <h2>Scan Result</h2>

          <p><b>Filename:</b> {result.filename}</p>
          <p><b>Verdict:</b> {result.final_verdict.verdict}</p>
          <p><b>Risk Score:</b> {result.final_verdict.risk_score}</p>

          <h3>Reasons</h3>
          <ul>
            {result.final_verdict.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>

          <button onClick={handleDownloadReport} style={{ marginTop: "15px" }}>
            Download PDF Report
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
