let lastReport = null;
const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;"
  }[c]));
}

async function postJSON(path, payload) {
  const res = await fetch(path, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}

$("scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = $("url").value.trim();
  if (!url) return;
  $("scanBtn").disabled = true;
  $("loading").classList.remove("hidden");
  $("error").classList.add("hidden");
  $("report").classList.add("hidden");
  try {
    lastReport = await postJSON("/api/scan", {url});
    renderReport(lastReport);
  } catch (error) {
    $("error").textContent = error.message;
    $("error").classList.remove("hidden");
  } finally {
    $("loading").classList.add("hidden");
    $("scanBtn").disabled = false;
  }
});

$("downloadBtn").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type:"application/json"});
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = "e1-watchdog-report.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
});

function renderReport(data) {
  $("report").classList.remove("hidden");
  $("targetName").textContent = data.target;
  $("scanMeta").textContent = \`${data.mode} · ${new Date(data.timestamp).toLocaleString()} · ${data.duration_ms} ms\`;
  $("score").textContent = data.score;
  $("critical").textContent = data.counts.critical || 0;
  $("high").textContent = data.counts.high || 0;
  $("medium").textContent = data.counts.medium || 0;
  $("lowInfo").textContent = (data.counts.low || 0) + (data.counts.info || 0);
  $("findingCount").textContent = \`${data.findings.length} findings\`;
  $("pages").textContent = \`${data.discovery.pages_scanned} pages\`;
  $("statusBadge").textContent = \`HTTP ${data.target_response.status}\`;
  const tlsText = data.tls?.available ? \`${data.tls.version || "TLS available"}${data.tls.cipher ? " · " + data.tls.cipher : ""}\` : "Not available / not verified";
  $("targetDetails").innerHTML = [
    ["Final URL", data.target_response.final_url],
    ["Content-Type", data.target_response.content_type || "—"],
    ["Server", data.target_response.server || "Not disclosed"],
    ["TLS", tlsText]
  ].map(([label,value]) => \`<div class="detail"><label>${esc(label)}</label><strong>${esc(value)}</strong></div>\`).join("");
  $("coverage").innerHTML = [
    \`Routes: ${data.discovery.endpoints.length}\`,
    \`JavaScript: ${data.discovery.javascript.length}\`,
    "Headers inspected", "TLS attempted", "Cookie flags observed",
    "Redirect targets validated"
  ].map(item => \`<span>${esc(item)}</span>\`).join("");

  $("findings").innerHTML = data.findings.length ? data.findings.map(item => \`
    <article class="finding">
      <div class="finding-top"><div class="finding-title">${esc(item.title)}</div>
        <span class="badge ${esc(item.severity)}">${esc(item.severity.toUpperCase())}</span></div>
      <p><b>Evidence:</b> ${esc(item.evidence)}</p>
      <p><b>Impact:</b> ${esc(item.impact)}</p>
      <p><b>Remediation:</b> ${esc(item.remediation)}</p>
      <div class="meta">${esc(item.category)} · Confidence: ${esc(item.confidence)} · ${esc(item.endpoint || "")}</div>
    </article>\`).join("") :
    \`<div class="finding"><div class="finding-title">No findings from current checks</div>
    <p>This does not mean the website is fully secure. Review the categories listed as not tested.</p></div>\`;
  $("tested").innerHTML = data.tested.map(item => \`<li>${esc(item)}</li>\`).join("");
  $("notTested").innerHTML = data.not_tested.map(item => \`<li>${esc(item)}</li>\`).join("");
}

$("deepBtn").addEventListener("click", async () => {
  const target = $("deepUrl").value.trim();
  const authorization = $("authorize").checked;
  const checks = [...document.querySelectorAll(".check-grid input:checked")].map(input => input.value);
  const box = $("deepResult");
  box.classList.remove("hidden");
  if (!authorization) { box.textContent = "Authorization confirmation is required."; return; }
  if (!target) { box.textContent = "Enter an authorized target."; return; }
  $("deepBtn").disabled = true;
  box.textContent = "Running owner-authorized review...";
  try {
    const data = await postJSON("/api/deep-assessment", {target, authorization, checks});
    box.innerHTML = \`<strong>Authorized review complete</strong><br>Target: ${esc(data.target)}<br>
      ${data.deep_review.map(item => \`<p><b>${esc(item.check)}</b> — ${esc(item.status)}<br>${esc(item.evidence)}</p>\`).join("")}
      <p class="lab-warning">This workflow does not perform auth bypass, password guessing, database dumping or destructive exploitation.</p>\`;
  } catch (error) {
    box.textContent = error.message;
  } finally {
    $("deepBtn").disabled = false;
  }
});

document.querySelectorAll(".lab-option").forEach((button) => {
  button.addEventListener("click", async () => {
    const box = $("labResult");
    box.classList.remove("hidden");
    box.textContent = "Loading offline synthetic scenario...";
    document.querySelectorAll(".lab-option").forEach(item => item.disabled = true);
    try {
      const data = await postJSON("/api/lab-simulation", {scenario: button.dataset.scenario});
      const item = data.result;
      box.innerHTML = \`<div class="lab-tags"><span>${esc(data.mode)}</span><span>Severity: ${esc(item.severity.toUpperCase())}</span>
          <span>Network requests: ${esc(data.network_requests)}</span><span>Target accessed: ${esc(String(data.target_accessed))}</span></div>
        <h4>${esc(item.title)}</h4><p><b>Status:</b> ${esc(item.status.replaceAll("_", " "))}</p>
        <p><b>Synthetic evidence:</b> ${esc(item.evidence)}</p><p><b>Potential impact:</b> ${esc(item.impact)}</p>
        <p><b>Remediation:</b> ${esc(item.remediation)}</p><p><b>Safe validation:</b> ${esc(item.safe_validation)}</p>
        <p class="lab-warning">${esc(data.notice)}</p>\`;
    } catch (error) {
      box.textContent = error.message;
    } finally {
      document.querySelectorAll(".lab-option").forEach(item => item.disabled = false);
    }
  });
});
