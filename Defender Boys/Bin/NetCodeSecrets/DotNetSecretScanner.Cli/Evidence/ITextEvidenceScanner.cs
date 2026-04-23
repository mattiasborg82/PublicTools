using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Evidence;

public interface ITextEvidenceScanner
{
    IReadOnlyList<Finding> ScanText(
        string content,
        string sourceKind,
        string filePath,
        string assemblyPath,
        string siteName,
        string applicationPath,
        string siteRoot,
        RuleSet ruleSet);
}