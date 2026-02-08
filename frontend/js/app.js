const API_URL = "http://localhost:8000/api/v1";

async function uploadZapReport() {
    const fileInput = document.getElementById('zapFile');
    const statusDiv = document.getElementById('zapStatus');

    if (fileInput.files.length === 0) {
        alert("Please select a file");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
        statusDiv.innerText = "Uploading...";
        const response = await fetch(`${API_URL}/reports/zap`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        if (response.ok) {
            statusDiv.innerText = `Success: ${data.count} vulnerabilities loaded.`;
        } else {
            statusDiv.innerText = `Error: ${data.detail}`;
        }
    } catch (error) {
        statusDiv.innerText = `Error: ${error.message}`;
    }
}

async function uploadLog() {
    const fileInput = document.getElementById('logFile');
    const logType = document.getElementById('logType').value;
    const statusDiv = document.getElementById('logStatus');

    if (fileInput.files.length === 0) {
        alert("Please select a file");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("log_type", logType);

    try {
        statusDiv.innerText = "Uploading...";
        const response = await fetch(`${API_URL}/logs/upload`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        if (response.ok) {
            statusDiv.innerText = `Success: ${data.count} log events loaded.`;
        } else {
            statusDiv.innerText = `Error: ${data.detail}`;
        }
    } catch (error) {
        statusDiv.innerText = `Error: ${error.message}`;
    }
}

async function runAnalysis() {
    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST'
        });

        const data = await response.json();
        if (response.ok) {
            alert(`Analysis Complete! Found ${data.chains_created} attack scenarios.`);
            displayScenarios(data.chains);
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (error) {
        console.error(error);
        alert("Analysis failed.");
    }
}

function displayScenarios(chains) {
    const resultsSection = document.getElementById('resultsSection');
    const list = document.getElementById('scenariosList');
    list.innerHTML = "";
    resultsSection.classList.remove('hidden');

    if (chains.length === 0) {
        list.innerHTML = "<p>No attack chains detected. Try adding more data or check constraints.</p>";
        return;
    }

    chains.forEach(chain => {
        const riskClass = chain.risk_score > 70 ? 'risk-high' : (chain.risk_score > 40 ? 'risk-medium' : 'risk-low');

        const div = document.createElement('div');
        div.className = 'scenario-item';
        // Flexbox header structure
        div.innerHTML = `
            <div class="scenario-header">
                <h3>${chain.name}</h3>
                <div class="risk-score ${riskClass}">Risk: ${chain.risk_score}</div>
            </div>
            <p><strong>Duration:</strong> ${new Date(chain.start_time).toLocaleString()} - ${new Date(chain.end_time).toLocaleString()}</p>
            <p><strong>Steps:</strong> ${chain.steps.length}</p>
            <p><strong>Source IPs:</strong> ${chain.source_ips.join(', ')}</p>
        `;
        div.onclick = () => showScenarioDetails(chain);
        list.appendChild(div);
    });
}

function showScenarioDetails(chain) {
    const modal = document.getElementById('scenarioModal');
    const title = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');

    title.innerText = chain.name;
    modal.style.display = "block";

    let html = `
        <div class="root-cause-box">
            <h3>Root Cause Analysis</h3>
            <p>${chain.root_cause_analysis}</p>
            <hr style="border-color: rgba(255,255,255,0.1); margin: 15px 0;">
            <p><small style="color: #cbd5e1;"><strong>ℹ️ Risk Score Calculation Model:</strong><br>
            The Risk Score (0-100) is calculated dynamically based on three factors:<br>
            1. <strong>Vulnerability Severity:</strong> High (+40), Medium (+20), Low (+10)<br>
            2. <strong>Log Anomalies:</strong> Server Errors (500s) add +10 points.<br>
            3. <strong>Attack Signatures:</strong> Detected patterns (e.g. 'UNION SELECT', '../etc/passwd') add +20 points.<br>
            <em>This scenario scored <strong>${chain.risk_score}</strong> based on these criteria.</em>
            </small></p>
        </div>
        <h3>Attack Timeline</h3>
    `;

    chain.steps.forEach(step => {
        html += `
            <div class="timeline-step">
                <div class="step-time">${new Date(step.timestamp).toLocaleString()}</div>
                <h4>${step.step_type}</h4>
                <p>${step.description}</p>
                ${step.related_vulnerability ? `<p><small>Vuln: ${step.related_vulnerability.name}</small></p>` : ''}
                ${step.related_logs.length > 0 ? `<p><small>Logs: ${step.related_logs.length} events</small></p>` : ''}
                ${step.related_logs.length > 0 ? `<pre style="background:#0f172a; padding:10px; overflow-x:auto; border:1px solid #334155;">${step.related_logs[0].raw_log}</pre>` : ''}
            </div>
        `;
    });

    body.innerHTML = html;
}

function closeModal() {
    document.getElementById('scenarioModal').style.display = "none";
}

// Close modal when clicking outside
window.onclick = function (event) {
    const modal = document.getElementById('scenarioModal');
    if (event.target == modal) {
        modal.style.display = "none";
    }
}

async function loadDemoData() {
    try {
        const response = await fetch(`${API_URL}/dev/populate`, {
            method: 'POST'
        });

        const data = await response.json();
        if (response.ok) {
            alert(data.message);
        } else {
            alert(`Error: ${data.detail}`);
        }
    } catch (error) {
        console.error(error);
        alert("Failed to load demo data. Make sure backend is running.");
    }
}
