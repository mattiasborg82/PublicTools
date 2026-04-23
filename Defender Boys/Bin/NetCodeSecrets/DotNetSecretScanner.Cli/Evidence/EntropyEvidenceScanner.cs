using System.Text.RegularExpressions;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Evidence;

public sealed class EntropyEvidenceScanner : IEntropyEvidenceScanner
{
    private static readonly Regex CandidateRegex = new(
        "[A-Za-z0-9+/=_\\-.]{20,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly IEntropyDetector _entropyDetector;

    public EntropyEvidenceScanner(IEntropyDetector entropyDetector)
    {
        _entropyDetector = entropyDetector ?? throw new ArgumentNullException(nameof(entropyDetector));
    }

    public IReadOnlyList<Finding> ScanText(
        string content,
        string sourceKind,
        string filePath,
        string assemblyPath,
        string siteName,
        string applicationPath,
        string siteRoot)
    {
        var findings = new List<Finding>();

        if (string.IsNullOrWhiteSpace(content))
        {
            return findings;
        }

        var matches = CandidateRegex.Matches(content);

        foreach (Match match in matches)
        {
            if (!_entropyDetector.IsHighEntropyCandidate(match.Value))
            {
                continue;
            }

            findings.Add(new Finding
            {
                RuleId = "high-entropy-candidate",
                Category = "unknown-secret",
                Severity = "medium",
		Confidence = "medium",
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