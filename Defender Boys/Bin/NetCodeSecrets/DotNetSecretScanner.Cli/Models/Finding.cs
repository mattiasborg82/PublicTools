namespace DotNetSecretScanner.Cli.Models;

public sealed class Finding
{
    public string RuleId { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Severity { get; set; } = string.Empty;

    public string Confidence { get; set; } = string.Empty;

    public string SourceKind { get; set; } = string.Empty;

    public string FilePath { get; set; } = string.Empty;

    public string AssemblyPath { get; set; } = string.Empty;

    public string HostName { get; set; } = string.Empty;

    public string SiteName { get; set; } = string.Empty;

    public string ApplicationPath { get; set; } = string.Empty;

    public string SiteRoot { get; set; } = string.Empty;

    public int? LineNumber { get; set; }

    public string Snippet { get; set; } = string.Empty;

    public string MatchedValue { get; set; } = string.Empty;
}