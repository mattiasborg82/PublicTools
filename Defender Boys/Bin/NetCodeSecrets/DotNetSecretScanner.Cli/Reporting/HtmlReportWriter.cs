using System.Net;
using System.Text;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Reporting;

public sealed class HtmlReportWriter
{
    public void Write(string path, IReadOnlyList<Finding> findings)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Output path must not be empty.", nameof(path));
        }

        if (findings is null)
        {
            throw new ArgumentNullException(nameof(findings));
        }

        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var html = BuildHtml(findings);
        File.WriteAllText(path, html, Encoding.UTF8);
    }

    private static string BuildHtml(IReadOnlyList<Finding> findings)
    {
        var totalFindings = findings.Count;
        var highCount = findings.Count(f => string.Equals(f.Severity, "high", StringComparison.OrdinalIgnoreCase));
        var mediumCount = findings.Count(f => string.Equals(f.Severity, "medium", StringComparison.OrdinalIgnoreCase));
        var entropyCount = findings.Count(f => string.Equals(f.RuleId, "high-entropy-candidate", StringComparison.OrdinalIgnoreCase));
        var ruleCount = totalFindings - entropyCount;

        var hostSummaries = findings
            .GroupBy(f => f.HostName, StringComparer.OrdinalIgnoreCase)
            .Select(g => new HostSummary
            {
                HostName = string.IsNullOrWhiteSpace(g.Key) ? "Unknown" : g.Key,
                Total = g.Count(),
                High = g.Count(f => string.Equals(f.Severity, "high", StringComparison.OrdinalIgnoreCase)),
                Medium = g.Count(f => string.Equals(f.Severity, "medium", StringComparison.OrdinalIgnoreCase)),
                Entropy = g.Count(f => string.Equals(f.RuleId, "high-entropy-candidate", StringComparison.OrdinalIgnoreCase))
            })
            .OrderByDescending(h => h.RiskScore)
            .ThenBy(h => h.HostName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var groupedFindings = findings
            .OrderBy(f => f.HostName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(f => GetSeverityRank(f.Severity))
            .ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
            .GroupBy(f => new { f.HostName, f.FilePath })
            .ToList();

        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"utf-8\" />");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
        sb.AppendLine("  <title>NetCodeSecrets Report</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    body { font-family: Arial, sans-serif; margin: 24px; background: #f5f5f5; color: #222; }");
        sb.AppendLine("    h1 { margin-bottom: 8px; }");
        sb.AppendLine("    h2 { margin: 0; font-size: 18px; }");
        sb.AppendLine("    h3 { margin: 0 0 10px 0; font-size: 16px; }");
        sb.AppendLine("    .conf-high { font-weight: bold; color: #2d6a4f; }");
        sb.AppendLine("    .conf-medium { font-weight: bold; color: #7a5200; }");
        sb.AppendLine("    .conf-low { font-weight: bold; color: #8b0000; }");
        sb.AppendLine("    .host-link { color: #1f3c88; text-decoration: underline; cursor: pointer; font-weight: bold; }");
        sb.AppendLine("    .reset-link { margin-left: 12px; color: #555; text-decoration: underline; cursor: pointer; }");
        sb.AppendLine("    .logo { display: flex; align-items: center; gap: 14px; margin-bottom: 18px; }");
        sb.AppendLine("    .logo-text { font-size: 24px; font-weight: bold; letter-spacing: 0.4px; }");
        sb.AppendLine("    .logo-sub { font-size: 12px; color: #666; margin-top: 2px; }");
        sb.AppendLine("    .subtitle { margin-bottom: 20px; color: #555; }");
        sb.AppendLine("    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }");
        sb.AppendLine("    .summary-card { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 14px; }");
        sb.AppendLine("    .summary-label { font-size: 12px; color: #666; margin-bottom: 6px; text-transform: uppercase; }");
        sb.AppendLine("    .summary-value { font-size: 28px; font-weight: bold; }");
        sb.AppendLine("    .legend { margin-bottom: 20px; padding: 12px; background: #fff; border: 1px solid #ddd; border-radius: 8px; }");
        sb.AppendLine("    .legend-item { display: inline-block; margin-right: 16px; margin-bottom: 8px; }");
        sb.AppendLine("    .filter-box { margin-bottom: 20px; padding: 12px; background: #fff; border: 1px solid #ddd; border-radius: 8px; }");
        sb.AppendLine("    .filter-label { display: block; font-size: 12px; color: #666; margin-bottom: 8px; text-transform: uppercase; }");
        sb.AppendLine("    .filter-input { width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #bbb; border-radius: 6px; font-size: 14px; }");
        sb.AppendLine("    .filter-help { margin-top: 8px; color: #666; font-size: 13px; }");
        sb.AppendLine("    .dashboard { margin-bottom: 20px; padding: 12px; background: #fff; border: 1px solid #ddd; border-radius: 8px; }");
        sb.AppendLine("    .dashboard table { width: 100%; border-collapse: collapse; background: #fff; }");
        sb.AppendLine("    .dashboard th, .dashboard td { border-top: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }");
        sb.AppendLine("    .dashboard th { background: #efefef; }");
        sb.AppendLine("    .risk-high { font-weight: bold; color: #8b0000; }");
        sb.AppendLine("    .risk-medium { font-weight: bold; color: #7a5200; }");
        sb.AppendLine("    .risk-low { font-weight: bold; color: #2d6a4f; }");
        sb.AppendLine("    .file-section { margin-bottom: 20px; background: #fff; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }");
        sb.AppendLine("    .file-header { padding: 14px; background: #f0f0f0; border-bottom: 1px solid #ddd; }");
        sb.AppendLine("    .file-path { font-family: Consolas, monospace; font-size: 14px; word-break: break-all; margin-top: 6px; }");
        sb.AppendLine("    .file-meta { margin-top: 6px; color: #666; font-size: 13px; }");
        sb.AppendLine("    .host-badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; background: #d9ead3; margin-bottom: 8px; }");
        sb.AppendLine("    table { width: 100%; border-collapse: collapse; background: #fff; }");
        sb.AppendLine("    th, td { border-top: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }");
        sb.AppendLine("    th { background: #efefef; }");
        sb.AppendLine("    .sev-high { font-weight: bold; color: #8b0000; }");
        sb.AppendLine("    .sev-medium { color: #7a5200; }");
        sb.AppendLine("    .mono { font-family: Consolas, monospace; word-break: break-all; }");
        sb.AppendLine("    .rule-row { background: #ffffff; }");
        sb.AppendLine("    .entropy-row { background: #fff8e1; }");
        sb.AppendLine("    .rule-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: bold; background: #e8f0fe; }");
        sb.AppendLine("    .entropy-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: bold; background: #ffe082; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"logo\">");
        sb.AppendLine("    <svg width=\"64\" height=\"64\" viewBox=\"0 0 64 64\" xmlns=\"http://www.w3.org/2000/svg\" aria-hidden=\"true\">");
        sb.AppendLine("      <defs>");
        sb.AppendLine("        <linearGradient id=\"ncGrad\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\">");
        sb.AppendLine("          <stop offset=\"0%\" stop-color=\"#1f3c88\" />");
        sb.AppendLine("          <stop offset=\"100%\" stop-color=\"#39a0ed\" />");
        sb.AppendLine("        </linearGradient>");
        sb.AppendLine("      </defs>");
        sb.AppendLine("      <rect x=\"6\" y=\"6\" width=\"52\" height=\"52\" rx=\"12\" fill=\"url(#ncGrad)\" />");
        sb.AppendLine("      <path d=\"M20 18 L20 46 L26 46 L26 29 L38 46 L44 46 L44 18 L38 18 L38 35 L26 18 Z\" fill=\"white\" />");
        sb.AppendLine("      <path d=\"M18 50 C24 44, 40 44, 46 50\" stroke=\"rgba(255,255,255,0.35)\" stroke-width=\"2\" fill=\"none\" />");
        sb.AppendLine("    </svg>");
        sb.AppendLine("    <div>");
        sb.AppendLine("      <div class=\"logo-text\">NetCodeSecrets</div>");
        sb.AppendLine("      <div class=\"logo-sub\">by Defender Boys | Dotnet Secrets Finder Tool</div>");
        sb.AppendLine("      <div class=\"subtitle\"></div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"summary-grid\">");
        AppendSummaryCard(sb, "Total Findings", totalFindings.ToString());
        AppendSummaryCard(sb, "High Severity", highCount.ToString());
        AppendSummaryCard(sb, "Medium Severity", mediumCount.ToString());
        AppendSummaryCard(sb, "Rule Matches", ruleCount.ToString());
        AppendSummaryCard(sb, "Entropy Matches", entropyCount.ToString());
        AppendSummaryCard(sb, "Host/File Groups", groupedFindings.Count.ToString());
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"legend\">");
        sb.AppendLine("    <div class=\"legend-item\"><span class=\"rule-badge\">Rule</span> Known pattern matched by a configured rule.</div>");
        sb.AppendLine("    <div class=\"legend-item\"><span class=\"entropy-badge\">Entropy</span> Unknown high-entropy candidate that may require analyst review.</div>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"dashboard\">");
        sb.AppendLine("    <h3>Host Summary Dashboard</h3>");
        sb.AppendLine("    <div style=\"margin-bottom:10px;\"><span class=\"reset-link\" onclick=\"clearFilter()\">Show all hosts</span></div>");
        sb.AppendLine("    <table>");
        sb.AppendLine("      <thead>");
        sb.AppendLine("        <tr>");
        sb.AppendLine("          <th>Host</th>");
        sb.AppendLine("          <th>Total</th>");
        sb.AppendLine("          <th>High</th>");
        sb.AppendLine("          <th>Medium</th>");
        sb.AppendLine("          <th>Entropy</th>");
        sb.AppendLine("          <th>Risk Score</th>");
        sb.AppendLine("        </tr>");
        sb.AppendLine("      </thead>");
        sb.AppendLine("      <tbody>");

        foreach (var host in hostSummaries)
        {
            var riskClass = GetRiskClass(host.RiskScore);

            sb.AppendLine("        <tr>");
            sb.AppendLine($"          <td><span class=\"host-link\" onclick=\"filterByHost('{HtmlEncode(JavaScriptEscape(host.HostName))}')\">{HtmlEncode(host.HostName)}</span></td>");            sb.AppendLine($"          <td>{host.High}</td>");
            sb.AppendLine($"          <td>{host.Medium}</td>");
            sb.AppendLine($"          <td>{host.Entropy}</td>");
            sb.AppendLine($"          <td class=\"{riskClass}\">{host.RiskScore}</td>");
            sb.AppendLine("        </tr>");
        }

        sb.AppendLine("      </tbody>");
        sb.AppendLine("    </table>");
        sb.AppendLine("  </div>");

        sb.AppendLine("  <div class=\"filter-box\">");
        sb.AppendLine("    <label class=\"filter-label\" for=\"filterInput\">Filter findings</label>");
        sb.AppendLine("    <input id=\"filterInput\" class=\"filter-input\" type=\"text\" placeholder=\"Search host, file path, rule, source, matched value, or snippet...\" oninput=\"applyFilter()\" />");
        sb.AppendLine("    <div class=\"filter-help\">Examples: server01, appsettings.json, bearer-token, managed-strings, Password=, entropy</div>");
        sb.AppendLine("  </div>");

        foreach (var fileGroup in groupedFindings)
        {
            var fileFindings = fileGroup.ToList();
            var fileHighCount = fileFindings.Count(f => string.Equals(f.Severity, "high", StringComparison.OrdinalIgnoreCase));
            var fileMediumCount = fileFindings.Count(f => string.Equals(f.Severity, "medium", StringComparison.OrdinalIgnoreCase));

            var sectionSearchText = string.Join(" ",
                fileFindings.Select(f => string.Join(" ",
                    f.HostName,
                    f.FilePath,
                    f.RuleId,
                    f.SourceKind,
                    f.MatchedValue,
                    f.Snippet,
                    f.Severity,
                    f.Category)));

            sb.AppendLine($"  <div class=\"file-section\" data-host=\"{HtmlEncode(fileGroup.Key.HostName)}\" data-search=\"{HtmlEncode(sectionSearchText)}\">");
            sb.AppendLine("    <div class=\"file-header\">");
            sb.AppendLine($"      <div class=\"host-badge\">Host: {HtmlEncode(fileGroup.Key.HostName)}</div>");
            sb.AppendLine($"      <h2>{HtmlEncode(Path.GetFileName(fileGroup.Key.FilePath))}</h2>");
            sb.AppendLine($"      <div class=\"file-path\">Full path: {HtmlEncode(fileGroup.Key.FilePath)}</div>");
            sb.AppendLine($"      <div class=\"file-meta\">Findings: {fileFindings.Count} | High: {fileHighCount} | Medium: {fileMediumCount}</div>");
            sb.AppendLine("    </div>");
            sb.AppendLine("    <table>");
            sb.AppendLine("      <thead>");
            sb.AppendLine("        <tr>");
            sb.AppendLine("          <th>Type</th>");
            sb.AppendLine("          <th>Rule</th>");
            sb.AppendLine("          <th>Severity</th>");
            sb.AppendLine("          <th>Confidence</th>");
            sb.AppendLine("          <th>Source</th>");
            sb.AppendLine("          <th>Matched Value</th>");
            sb.AppendLine("          <th>Snippet</th>");
            sb.AppendLine("        </tr>");
            sb.AppendLine("      </thead>");
            sb.AppendLine("      <tbody>");

            foreach (var finding in fileFindings)
            {
                var severityClass = GetSeverityClass(finding.Severity);
                var isEntropy = string.Equals(finding.RuleId, "high-entropy-candidate", StringComparison.OrdinalIgnoreCase);
                var rowClass = isEntropy ? "entropy-row" : "rule-row";
                var badgeClass = isEntropy ? "entropy-badge" : "rule-badge";
                var badgeText = isEntropy ? "Entropy" : "Rule";
                var confidenceClass = GetConfidenceClass(finding.Confidence);

                sb.AppendLine($"        <tr class=\"{rowClass}\">");
                sb.AppendLine($"          <td><span class=\"{badgeClass}\">{badgeText}</span></td>");
                sb.AppendLine($"          <td>{HtmlEncode(finding.RuleId)}</td>");
                sb.AppendLine($"          <td class=\"{severityClass}\">{HtmlEncode(finding.Severity)}</td>");
                sb.AppendLine($"          <td class=\"{confidenceClass}\">{HtmlEncode(finding.Confidence)}</td>");
                sb.AppendLine($"          <td>{HtmlEncode(finding.SourceKind)}</td>");
                sb.AppendLine($"          <td class=\"mono\">{HtmlEncode(finding.MatchedValue)}</td>");
                sb.AppendLine($"          <td>{HtmlEncode(finding.Snippet)}</td>");
                sb.AppendLine("        </tr>");
            }

            sb.AppendLine("      </tbody>");
            sb.AppendLine("    </table>");
            sb.AppendLine("  </div>");
        }

                sb.AppendLine("  <script>");
        sb.AppendLine("    function applyFilter() {");
        sb.AppendLine("      var input = document.getElementById('filterInput');");
        sb.AppendLine("      var filter = input.value.toLowerCase();");
        sb.AppendLine("      var sections = document.querySelectorAll('.file-section');");
        sb.AppendLine("      for (var i = 0; i < sections.length; i++) {");
        sb.AppendLine("        var section = sections[i];");
        sb.AppendLine("        var text = (section.getAttribute('data-search') || '').toLowerCase();");
        sb.AppendLine("        section.style.display = text.indexOf(filter) >= 0 ? '' : 'none';");
        sb.AppendLine("      }");
        sb.AppendLine("    }");
        sb.AppendLine("    function filterByHost(hostName) {");
        sb.AppendLine("      var input = document.getElementById('filterInput');");
        sb.AppendLine("      input.value = hostName;");
        sb.AppendLine("      applyFilter();");
        sb.AppendLine("    }");
        sb.AppendLine("    function clearFilter() {");
        sb.AppendLine("      var input = document.getElementById('filterInput');");
        sb.AppendLine("      input.value = '';");
        sb.AppendLine("      applyFilter();");
        sb.AppendLine("    }");
        sb.AppendLine("  </script>");

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private static void AppendSummaryCard(StringBuilder sb, string label, string value)
    {
        sb.AppendLine("    <div class=\"summary-card\">");
        sb.AppendLine($"      <div class=\"summary-label\">{HtmlEncode(label)}</div>");
        sb.AppendLine($"      <div class=\"summary-value\">{HtmlEncode(value)}</div>");
        sb.AppendLine("    </div>");
    }

    private static int GetSeverityRank(string severity)
    {
        if (string.Equals(severity, "high", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        if (string.Equals(severity, "medium", StringComparison.OrdinalIgnoreCase))
        {
            return 1;
        }

        return 0;
    }
     private static string GetConfidenceClass(string confidence)
    {
        if (string.Equals(confidence, "high", StringComparison.OrdinalIgnoreCase))
        {
            return "conf-high";
        }

        if (string.Equals(confidence, "medium", StringComparison.OrdinalIgnoreCase))
        {
            return "conf-medium";
        }

        if (string.Equals(confidence, "low", StringComparison.OrdinalIgnoreCase))
        {
            return "conf-low";
        }

        return string.Empty;
    }

    private static string GetSeverityClass(string severity)
    {
        if (string.Equals(severity, "high", StringComparison.OrdinalIgnoreCase))
        {
            return "sev-high";
        }

        if (string.Equals(severity, "medium", StringComparison.OrdinalIgnoreCase))
        {
            return "sev-medium";
        }

        return string.Empty;
    }

    private static string GetRiskClass(int riskScore)
    {
        if (riskScore >= 15)
        {
            return "risk-high";
        }

        if (riskScore >= 6)
        {
            return "risk-medium";
        }

        return "risk-low";
    }
    
    private static string JavaScriptEscape(string value)
    {
        return (value ?? string.Empty).Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal);
    }
    private static string HtmlEncode(string value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty);
    }


    private sealed class HostSummary
    {
        public string HostName { get; set; } = string.Empty;
        public int Total { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Entropy { get; set; }
        public int RiskScore => (High * 5) + (Medium * 2) + Entropy;
    }
}