namespace DotNetSecretScanner.Cli.Models;

public sealed class EntropyFinding
{
    public string SourceKind { get; set; } = string.Empty;

    public string FilePath { get; set; } = string.Empty;

    public string AssemblyPath { get; set; } = string.Empty;

    public string SiteName { get; set; } = string.Empty;

    public string ApplicationPath { get; set; } = string.Empty;

    public string SiteRoot { get; set; } = string.Empty;

    public int? LineNumber { get; set; }

    public string Snippet { get; set; } = string.Empty;

    public string MatchedValue { get; set; } = string.Empty;
}