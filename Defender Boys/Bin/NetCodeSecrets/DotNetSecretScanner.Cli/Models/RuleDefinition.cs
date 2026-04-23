namespace DotNetSecretScanner.Cli.Models;

public sealed class RuleDefinition
{
    public string Id { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Severity { get; set; } = string.Empty;

    public string Engine { get; set; } = string.Empty;

    public string Pattern { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;
}