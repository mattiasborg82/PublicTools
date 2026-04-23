using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Evidence;

public interface IRuleLoader
{
    RuleSet Load(string path);
}