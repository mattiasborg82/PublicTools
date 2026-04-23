using System.Text.Json;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Evidence;

public sealed class JsonRuleLoader : IRuleLoader
{
    public RuleSet Load(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Rules path must not be empty.", nameof(path));
        }

        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Rules file was not found.", path);
        }

        var json = File.ReadAllText(path);

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        var ruleSet = JsonSerializer.Deserialize<RuleSet>(json, options);

        if (ruleSet is null)
        {
            throw new InvalidOperationException("Rules file could not be deserialized.");
        }

        if (ruleSet.Rules is null)
        {
            throw new InvalidOperationException("Rules file does not contain a rules collection.");
        }

        return ruleSet;
    }
}