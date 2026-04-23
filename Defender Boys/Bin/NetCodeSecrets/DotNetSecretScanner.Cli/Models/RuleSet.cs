namespace DotNetSecretScanner.Cli.Models;

public sealed class RuleSet
{
    public int Version { get; set; }

    public List<RuleDefinition> Rules { get; set; } = new();
}