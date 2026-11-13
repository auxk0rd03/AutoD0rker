use rusqlite::{Connection, params};

pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn sev_css_class(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" | "HIGH" => "sev-badge sev-high",
        "MEDIUM" => "sev-badge sev-med",
        "LOW" => "sev-badge sev-low",
        _ => "sev-badge sev-info",
    }
}

/// Renders verified findings for a scan or batch directly as HTMX fragments
/// with Out-of-Band (`hx-swap-oob="true"`) KPI strip updates.
pub fn render_scan_htmx_response(
    conn: &Connection,
    scan_id: i64,
    batch_id: &str,
) -> Result<String, String> {
    let mut stmt = conn
        .prepare(
            "SELECT df.finding_id, df.scan_id, df.severity, dc.category, dc.dork_string,
                    df.matched_endpoint, df.ast_node_type, df.ast_context_snippet,
                    df.shannon_entropy_bps, df.confidence_bps, df.cwe_id, df.cvss_vector,
                    df.stealth_curl_poc
             FROM dork_findings df
             JOIN dork_catalog dc ON df.dork_id = dc.dork_id
             JOIN scan_sessions ss ON df.scan_id = ss.scan_id
             WHERE ss.batch_id = ?1
             ORDER BY
               CASE df.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
               df.finding_id DESC",
        )
        .map_err(|e| e.to_string())?;

    let mut rows_html = String::with_capacity(4096);
    let mut row_count = 0usize;

    let rows = stmt
        .query_map(params![batch_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, String>(10)?,
                r.get::<_, String>(11)?,
                r.get::<_, String>(12)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for item in rows {
        let (
            fid,
            sid,
            sev,
            cat,
            dork,
            endpoint,
            ast_node,
            snippet,
            entropy_bps,
            conf_bps,
            cwe,
            _cvss,
            curl_poc,
        ) = item.map_err(|e| e.to_string())?;

        row_count += 1;
        let entropy_str = format!("{:.2} b", entropy_bps as f64 / 100.0);
        let conf_str = format!("{:.0}%", conf_bps as f64 / 100.0);

        rows_html.push_str(&format!(
            r#"<tr id="finding-row-{fid}">
  <td class="val-muted">#{fid:03}</td>
  <td><span class="{sev_cls}">{sev}</span></td>
  <td>
    <div class="finding-cat">{cat_esc}</div>
    <div class="finding-dork val-muted">{dork_esc}</div>
    <div class="finding-url"><a href="{ep_esc}" target="_blank" rel="noopener noreferrer">{ep_esc}</a></div>
    <div class="finding-snippet val-muted">[{cwe_esc}] {snip_esc}</div>
  </td>
  <td class="num-right">
    <div>{entropy_str}</div>
    <div class="val-pos">{ast_esc} ({conf_str})</div>
  </td>
  <td class="actions-cell">
    <button type="button" class="btn-mini" data-curl="{curl_esc}" onclick="copyCurlPoC(this)">[cURL]</button>
    <a class="btn-mini" href="/api/export/md/{sid}">[.MD]</a>
    <a class="btn-mini" href="/api/export/docx/{sid}">[.DOCX]</a>
  </td>
</tr>"#,
            fid = fid,
            sid = sid,
            sev_cls = sev_css_class(&sev),
            sev = escape_html(&sev),
            cat_esc = escape_html(&cat),
            dork_esc = escape_html(&dork),
            ep_esc = escape_html(&endpoint),
            cwe_esc = escape_html(&cwe),
            snip_esc = escape_html(&snippet),
            entropy_str = entropy_str,
            ast_esc = escape_html(&ast_node),
            conf_str = conf_str,
            curl_esc = escape_html(&curl_poc),
        ));
    }

    if row_count == 0 {
        rows_html.push_str(
            r#"<tr><td colspan="5" class="val-muted" style="text-align:center;padding:18px;">[NO VERIFIED EXPOSURES MATCHED AST + SHANNON ENTROPY GATES]</td></tr>"#,
        );
    }

    let (targets, dorks_run, verified_tp, fp_dropped, max_risk) =
        crate::db::query_batch_kpis(conn, batch_id).map_err(|e| e.to_string())?;

    let risk_cls = if max_risk >= 70 {
        "val-neg"
    } else if max_risk >= 40 {
        "val-warn"
    } else {
        "val-pos"
    };

    let mut out = String::with_capacity(rows_html.len() + 1024);
    out.push_str(&format!(
        r#"<div id="scan-status-banner" class="panel-status val-pos">[SCAN #{scan_id} COMPLETE // BATCH {batch_esc} // VERIFIED: {verified_tp} // FP DROPPED: {fp_dropped}]</div>"#,
        scan_id = scan_id,
        batch_esc = escape_html(batch_id),
        verified_tp = verified_tp,
        fp_dropped = fp_dropped,
    ));

    out.push_str(r#"<tbody id="dork-findings-tbody" hx-swap-oob="innerHTML">"#);
    out.push_str(&rows_html);
    out.push_str("</tbody>");

    out.push_str(&format!(
        r#"<div id="kpi-targets" hx-swap-oob="innerHTML"><span class="kpi-label">TARGETS</span><span class="kpi-val">{targets:02}</span></div>
<div id="kpi-dorks-run" hx-swap-oob="innerHTML"><span class="kpi-label">EVALUATED</span><span class="kpi-val">{dorks_run}</span></div>
<div id="kpi-verified-tp" hx-swap-oob="innerHTML"><span class="kpi-label">VERIFIED TP</span><span class="kpi-val val-pos">{verified_tp:02}</span></div>
<div id="kpi-ast-fp-drop" hx-swap-oob="innerHTML"><span class="kpi-label">SUPPRESSED FP</span><span class="kpi-val val-warn">{fp_dropped:02}</span></div>
<div id="kpi-risk-score" hx-swap-oob="innerHTML"><span class="kpi-label">MAX RISK</span><span class="kpi-val {risk_cls}">{max_risk}/100</span></div>"#,
        targets = targets,
        dorks_run = dorks_run,
        verified_tp = verified_tp,
        fp_dropped = fp_dropped,
        risk_cls = risk_cls,
        max_risk = max_risk,
    ));

    Ok(out)
}
