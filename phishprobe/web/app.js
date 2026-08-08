/*
 * Author: Sathyanarayana
 *
 * PhishProbe front-end renderer.
 * Served by app.py at /app.js. Shared by the header analyzer (/) and the
 * full email analyzer (/full). Posts to the matching API endpoint and renders
 * the returned report JSON into the #results element.
 *
 * Input is always an email header / raw message (or an uploaded .eml / .txt
 * file) - there is no standalone URL analyzer anymore.
 */

(function () {
  "use strict";

  var $ = function (sel) { return document.querySelector(sel); };

  var PAGE_IS_FULL = !!document.getElementById("email-input");

  var ENDPOINT = PAGE_IS_FULL ? "/api/analyze" : "/api/analyze-header";
  var INPUT_SEL = PAGE_IS_FULL ? "#email-input" : "#header-input";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function verdictClass(v) {
    return "verdict-" + String(v || "unknown").toLowerCase();
  }

  function chipClass(v) {
    var map = {
      "pass": "safe",
      "fail": "malicious",
      "malicious": "malicious",
      "suspicious": "suspicious",
      "moderate": "moderate",
      "safe": "safe",
      "not verified": "neutral",
      "not found": "neutral",
      "unknown": "neutral"
    };
    var key = String(v || "unknown").toLowerCase();
    return map[key] || "neutral";
  }

  function chip(label, cls) {
    return '<span class="chip ' + chipClass(cls) + '">' + esc(label) + "</span>";
  }

  function countsRow(counts) {
    var parts = [];
    var labels = { malicious: "malicious", suspicious: "suspicious", safe: "safe", unknown: "unknown" };
    for (var key in labels) {
      if (counts && counts[key] !== undefined) {
        parts.push(chip(labels[key] + ": " + counts[key], key));
      }
    }
    return parts.length ? '<div class="chips">' + parts.join("") + "</div>" : "";
  }

  function section(title, inner) {
    return '<section class="block"><h2>' + esc(title) + "</h2>" + inner + "</section>";
  }

  // ------------------------------------------------------------------ banner

  function renderSummary(summary) {
    var v = summary.verdict;
    var note =
      '<div class="banner-note"><span class="banner-note-icon">&#9888;</span><span>' +
        "Before taking any action, cross-check the identified indicators (IOCs) against " +
        "independent threat-intelligence platforms (e.g., urlscan.io, AbuseIPDB, AlienVault OTX). " +
        'A detection count of &quot;0/91&quot; only means no engine has flagged the indicator ' +
        "yet - it is not proof that it is safe. Following the zero-trust principle, never trust, " +
        "always verify - we recommend manually confirming the flagged domains and URLs before " +
        "proceeding." +
      "</span></div>";
    return (
      '<div class="banner ' + verdictClass(v) + '">' +
        '<div class="v-line">' +
          '<span class="v-title">' + esc(v) + "</span>" +
          '<span class="v-conf">Confidence ' + esc(summary.confidence) + "%</span>" +
        "</div>" +
        "<p>" + esc(summary.explanation) + "</p>" +
        countsRow(summary.counts) +
        '<div class="conf-meter"><div class="fill ' + verdictClass(v) +
          '" style="width:' + Math.min(100, summary.confidence || 0) + '%"></div></div>' +
        '<div class="rec"><strong>Recommendation:</strong> ' +
          esc(summary.recommendation) + "</div>" +
        note +
      "</div>"
    );
  }

  // --------------------------------------------------------------- email info

  function renderEmail(email) {
    var cells = [
      ["From", email.from], ["To", email.to], ["Subject", email.subject],
      ["Reply-To", email.reply_to], ["Return-Path", email.return_path],
      ["Message-ID domain", email.message_id_domain]
    ];
    var html = '<div class="info-grid">';
    cells.forEach(function (c) {
      html += '<div class="info-cell"><div class="k">' + esc(c[0]) +
              '</div><div class="val">' + esc(c[1]) + "</div></div>";
    });
    return html + "</div>";
  }

  // ------------------------------------------------------------- auth status

  // Show only the final status per protocol (Pass / Fail / Not found) with the
  // traffic-light colouring - no raw token dump.
  function renderAuth(auth) {
    var protos = ["spf", "dkim", "dmarc", "arc"];
    var html = '<div class="info-grid">';
    protos.forEach(function (p) {
      var e = (auth && auth[p]) || { status: "Not found" };
      html +=
        '<div class="info-cell"><div class="k">' + p.toUpperCase() +
        '</div><div class="val">' + chip(e.status, e.status) + "</div></div>";
    });
    return html + "</div>";
  }

  // ------------------------------------------------------------- indicators

  function indicatorRow(item) {
    var value = item.value;
    var detail = "";
    if (item.type === "File") {
      value = item.filename || item.value;
      detail = "SHA-256: " + item.sha256;
    }
    var extra = [];
    if (item.malware_family) extra.push(item.malware_family);
    if (item.note) extra.push(item.note);
    return (
      "<tr>" +
        '<td data-label="Type">' + esc(item.type) + "</td>" +
        '<td class="mono" data-label="Indicator">' + esc(value) + "</td>" +
        '<td data-label="Verdict">' + chip(item.verdict || "Unknown", item.verdict || "unknown") + "</td>" +
        '<td data-label="Details">' + esc(extra.join(" &middot; ")) + "</td>" +
      "</tr>"
    );
  }

  function indicatorTable(title, items) {
    if (!items || !items.length) return "";
    var rows = items.map(indicatorRow).join("");
    return (
      '<section class="block"><h2>' + esc(title) + " (" + items.length + ")</h2>" +
        '<div class="table-wrap"><table class="tbl"><thead><tr><th>Type</th><th>Indicator</th>' +
        "<th>Verdict</th><th>Details</th></tr></thead><tbody>" + rows +
        "</tbody></table></div></section>"
    );
  }

  function renderIndicators(indicators) {
    if (!indicators) return "";
    var html = "";
    html += indicatorTable("URLs", indicators.urls);
    html += indicatorTable("Domains", indicators.domains);
    html += indicatorTable("IP addresses", indicators.ips);
    html += indicatorTable("Attachments (hashes)", indicators.files);
    return html;
  }

  // ------------------------------------------------------------------- local

  function findingsBlock(title, items) {
    if (!items || !items.length) return "";
    var html = items.map(function (f) {
      var sev = f.severity || "info";
      return (
        '<div class="find-item"><span class="dot ' + esc(sev) + '"></span>' +
        "<div>" + esc(f.message) + (f.learn ? '<span class="learn">' + esc(f.learn) + "</span>" : "") +
        "</div></div>"
      );
    }).join("");
    return '<section class="block"><h2>' + esc(title) + " (" + items.length + ")</h2>" + html + "</section>";
  }

  function renderLocal(local) {
    if (!local) return "";
    var html = "";
    html += findingsBlock("From / Reply-To / Return-Path mismatches", local.mismatches);
    html += findingsBlock("Link anomalies", local.link_anomalies);
    html += findingsBlock("Brand typosquatting", local.typosquatting);
    if (local.content) {
      var c = local.content;
      html += findingsBlock("Urgency / credential phrases", (c.urgency || []).map(function (p) {
        return { severity: "low", message: "Urgency / credential-related phrase in body: '" + p + "'" };
      }));
      html += findingsBlock("Malware-related keywords", (c.malware || []).map(function (w) {
        return { severity: "low", message: "Malware-related keyword mentioned in body: '" + w + "'" };
      }));
      if (c.generic_greeting) {
        html += findingsBlock("Generic greeting", [{ severity: "low", message: "Generic greeting detected (common in mass-phishing campaigns)." }]);
      }
    }
    return html;
  }

  // ---------------------------------------------------------------- attachments

  function renderAttachments(attachments) {
    if (!attachments || !attachments.length) {
      return '<section class="block"><h2>Attachments</h2>' +
             '<div class="empty-note">No attachments found.</div></section>';
    }
    var rows = attachments.map(function (a) {
      var risk = a.dangerous
        ? '<span class="chip malicious">dangerous</span>'
        : '<span class="chip safe">ok</span>';
      return (
        "<tr>" +
          '<td data-label="Name">' + esc(a.filename) + "</td>" +
          '<td data-label="Type">' + esc(a.content_type) + "</td>" +
          '<td data-label="Size">' + esc(a.size) + " bytes</td>" +
          '<td data-label="Ext">' + esc(a.extension) + "</td>" +
          '<td data-label="Risk">' + risk + "</td>" +
        "</tr>"
      );
    }).join("");
    return (
      '<section class="block"><h2>Attachments (' + attachments.length + ")</h2>" +
      '<div class="table-wrap"><table class="tbl"><thead><tr><th>Name</th><th>Type</th><th>Size</th>' +
      "<th>Ext</th><th>Risk</th></tr></thead><tbody>" + rows +
      "</tbody></table></div></section>"
    );
  }

  // ------------------------------------------------------------------- emails

  function renderEmails(emails) {
    if (!emails || !emails.length) return "";
    return section("Email addresses found", emails.map(function (e) {
      return '<span class="mono">' + esc(e) + "</span>";
    }).join("<br>"));
  }

  // ------------------------------------------------------------------ report

  function renderReport(report) {
    var html = "";
    html += renderSummary(report.summary);
    html += section("Email summary", renderEmail(report.email));
    html += section("Authentication (SPF / DKIM / DMARC / ARC)", renderAuth(report.header.auth));
    html += renderEmails(report.indicators.emails);
    html += renderIndicators(report.indicators);
    html += renderLocal(report.local);
    html += renderAttachments(report.attachments);
    return html;
  }

  // ------------------------------------------------------- manual verification

  // Collect every indicator security engines (or inherited verdicts) flagged.
  function flaggedIndicators(report) {
    var out = [];
    var groups = ["urls", "domains", "ips", "files"];
    var inds = (report && report.indicators) || {};
    groups.forEach(function (g) {
      (inds[g] || []).forEach(function (item) {
        if (item.verdict === "Malicious" || item.verdict === "Suspicious") {
          out.push(item);
        }
      });
    });
    return out;
  }

  // One clickable row of independent threat-intel check sites per indicator.
  function verifyLinks(item) {
    var v = item.value;
    var host = v;
    if (/^https?:\/\//i.test(v)) {
      try { host = new URL(v).hostname; } catch (e) { /* keep raw */ }
    }
    var links = [];
    if (item.type === "IP") {
      links.push('<a class="v-link" href="https://www.abuseipdb.com/check/' +
                 encodeURIComponent(v) + '" target="_blank" rel="noopener">AbuseIPDB</a>');
      links.push('<a class="v-link" href="https://otx.alienvault.com/indicator/ip/' +
                 encodeURIComponent(v) + '" target="_blank" rel="noopener">AlienVault OTX</a>');
      links.push('<a class="v-link" href="https://www.robtex.com/ip-lookup/' +
                 encodeURIComponent(v) + '" target="_blank" rel="noopener">Robtex</a>');
    } else {
      links.push('<a class="v-link" href="https://urlscan.io/search/#' +
                 encodeURIComponent(item.type === "URL" ? v : host) +
                 '" target="_blank" rel="noopener">urlscan.io</a>');
      links.push('<a class="v-link" href="https://www.urlvoid.com/scan/' +
                 encodeURIComponent(host) + '/" target="_blank" rel="noopener">URLVoid</a>');
      if (item.type === "Domain") {
        links.push('<a class="v-link" href="https://www.abuseipdb.com/whois/' +
                   encodeURIComponent(host) + '" target="_blank" rel="noopener">AbuseIPDB</a>');
      }
    }
    return links;
  }

  // Popup shown after analysis when something was flagged - nudges the user to
  // double-check each indicator on independent threat-intel sites. Nothing is
  // shown when everything is clean (nothing to verify).
  function showVerifyModal(report) {
    var flagged = flaggedIndicators(report);
    if (!flagged.length) return;
    var rows = flagged.map(function (item) {
      return "<tr>" +
               '<td class="mono" data-label="Indicator">' + esc(item.value) + "</td>" +
               '<td data-label="Verdict">' + chip(item.verdict, item.verdict) + "</td>" +
               '<td data-label="Check on">' + verifyLinks(item).join("") + "</td>" +
             "</tr>";
    }).join("");
    var html =
      '<div class="modal-overlay" id="verify-modal">' +
        '<div class="modal" role="dialog" aria-modal="true" aria-label="Manual verification">' +
          '<button type="button" class="modal-close" data-close aria-label="Close">&times;</button>' +
          "<h2>Verify before you act</h2>" +
          '<p class="modal-intro">PhishProbe flagged the indicators below. The verdict is automated - ' +
          "confirm each one yourself on an independent threat-intel site before opening " +
          "links or replying.</p>" +
          '<div class="table-wrap"><table class="tbl"><thead>' +
          "<tr><th>Indicator</th><th>Verdict</th><th>Check on</th></tr></thead>" +
          "<tbody>" + rows + "</tbody></table></div>" +
          '<div class="modal-actions"><button type="button" class="btn" data-close>Close</button></div>' +
        "</div>" +
      "</div>";
    var wrap = document.createElement("div");
    wrap.innerHTML = html;
    document.body.appendChild(wrap.firstChild);

    var el = document.getElementById("verify-modal");
    function close() {
      if (el && el.parentNode) el.parentNode.removeChild(el);
      document.removeEventListener("keydown", onKey);
    }
    function onKey(e) { if (e.key === "Escape") close(); }
    el.querySelectorAll("[data-close]").forEach(function (b) {
      b.addEventListener("click", close);
    });
    el.addEventListener("click", function (e) { if (e.target === el) close(); });
    document.addEventListener("keydown", onKey);
  }

  // -------------------------------------------------------------- interaction

  function setLoading(on) {
    var btn = $("#analyze-btn");
    if (!btn) return;
    btn.disabled = on;
    btn.innerHTML = on
      ? '<span class="spinner"></span> Analyzing... (may take ~30s)'
      : "Analyze";
  }

  function showError(msg) {
    $("#results").innerHTML = '<div class="error-box">' + esc(msg) + "</div>";
  }

  function analyze() {
    var input = $(INPUT_SEL);
    var text = (input && input.value || "").trim();

    if (!text) {
      showError("Nothing to analyze yet - paste a header, an email, or upload a file.");
      return;
    }

    var body;
    var endpoint = ENDPOINT;
    if (PAGE_IS_FULL) {
      body = { raw: text };
    } else {
      body = { header: text };
    }

    setLoading(true);
    $("#results").innerHTML = "";
    fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        setLoading(false);
        if (data.error) {
          showError("Analysis failed: " + data.error);
          return;
        }
        $("#results").innerHTML = renderReport(data);
        showVerifyModal(data);
        $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
      })
      .catch(function (err) {
        setLoading(false);
        showError("Request failed: " + err.message);
      });
  }

  // File upload: read a .eml / .txt file into the textarea.
  function wireUpload() {
    var upBtn = $("#upload-btn");
    var fileInput = $("#file-input");
    var textArea = $(INPUT_SEL);
    if (!upBtn || !fileInput || !textArea) return;
    upBtn.addEventListener("click", function () {
      fileInput.value = "";
      fileInput.click();
    });
    fileInput.addEventListener("change", function () {
      var file = fileInput.files && fileInput.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        textArea.value = String(reader.result || "");
        upBtn.innerHTML = "Upload file";
      };
      upBtn.innerHTML = "Reading " + esc(file.name) + "...";
      reader.readAsText(file);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireUpload();
    var btn = $("#analyze-btn");
    if (btn) {
      btn.addEventListener("click", analyze);
      var inp = $(INPUT_SEL);
      if (inp) {
        inp.addEventListener("keydown", function (e) {
          if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze();
        });
      }
    }
  });
})();
