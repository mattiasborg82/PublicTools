using System.Text.RegularExpressions;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Evidence;

public sealed class RegexTextEvidenceScanner : ITextEvidenceScanner
{
    public IReadOnlyList<Finding> ScanText(
        string content,
        string sourceKind,
        string filePath,
        string assemblyPath,
        string siteName,
        string applicationPath,
        string siteRoot,
        RuleSet ruleSet)
    {
        var findings = new List<Finding>();

        if (string.IsNullOrEmpty(content))
        {
            return findings;
        }

        if (ruleSet is null)
        {
            throw new ArgumentNullException(nameof(ruleSet));
        }

        foreach (var rule in ruleSet.Rules)
        {
            if (!string.Equals(rule.Engine, "regex", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(rule.Pattern))
            {
                continue;
            }

            var regex = new Regex(rule.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            var matches = regex.Matches(content);

            foreach (Match match in matches)
            {
                findings.Add(new Finding
                {
                    RuleId = rule.Id,
                    Category = rule.Category,
                    Severity = rule.Severity,
                    Confidence = "high",
                    SourceKind = sourceKind,
                    FilePath = filePath,
                    AssemblyPath = assemblyPath,
                    HostName = Environment.MachineName,
                    SiteName = siteName,
                    ApplicationPath = applicationPath,
                    SiteRoot = siteRoot,
                    LineNumber = GetLineNumber(content, match.Index),
                    Snippet = GetSnippet(content, match.Index, match.Length),
                    MatchedValue = match.Value
                });
            }
        }

        return findings;
    }

    private static int GetLineNumber(string content, int index)
    {
        var lineNumber = 1;

        for (var i = 0; i < index && i < content.Length; i++)
        {
            if (content[i] == '\n')
            {
                lineNumber++;
            }
        }

        return lineNumber;
    }

    private static string GetSnippet(string content, int index, int length)
    {
        const int maxSnippetLength = 200;

        var start = Math.Max(0, index - 40);
        var end = Math.Min(content.Length, index + length + 40);
        var snippet = content.Substring(start, end - start);

        snippet = snippet.Replace("\r", " ").Replace("\n", " ").Trim();

        if (snippet.Length > maxSnippetLength)
        {
            snippet = snippet.Substring(0, maxSnippetLength);
        }

        return snippet;
    }
}