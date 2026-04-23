using DotNetSecretScanner.Cli.Decompilation;
using DotNetSecretScanner.Cli.Discovery;
using DotNetSecretScanner.Cli.Evidence;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Scanner;

public sealed class ScanOrchestrator
{
    private readonly IAppDiscovery _appDiscovery;
    private readonly IRuleLoader _ruleLoader;
    private readonly ITextEvidenceScanner _textEvidenceScanner;
    private readonly IEntropyEvidenceScanner _entropyEvidenceScanner;
    private readonly IDecompilerAdapter _decompilerAdapter;
    private readonly IBinaryStringExtractor _binaryStringExtractor;
    private readonly IManagedStringExtractor _managedStringExtractor;

    public ScanOrchestrator(
        IAppDiscovery appDiscovery,
        IRuleLoader ruleLoader,
        ITextEvidenceScanner textEvidenceScanner,
        IEntropyEvidenceScanner entropyEvidenceScanner,
        IDecompilerAdapter decompilerAdapter,
        IBinaryStringExtractor binaryStringExtractor,
        IManagedStringExtractor managedStringExtractor)
    {
        _appDiscovery = appDiscovery ?? throw new ArgumentNullException(nameof(appDiscovery));
        _ruleLoader = ruleLoader ?? throw new ArgumentNullException(nameof(ruleLoader));
        _textEvidenceScanner = textEvidenceScanner ?? throw new ArgumentNullException(nameof(textEvidenceScanner));
        _entropyEvidenceScanner = entropyEvidenceScanner ?? throw new ArgumentNullException(nameof(entropyEvidenceScanner));
        _decompilerAdapter = decompilerAdapter ?? throw new ArgumentNullException(nameof(decompilerAdapter));
        _binaryStringExtractor = binaryStringExtractor ?? throw new ArgumentNullException(nameof(binaryStringExtractor));
        _managedStringExtractor = managedStringExtractor ?? throw new ArgumentNullException(nameof(managedStringExtractor));
    }

    public IReadOnlyList<Finding> Scan(string rootPath, string rulesPath)
    {
        var targets = _appDiscovery.Discover(rootPath);
        return ScanTargets(targets, rulesPath);
    }

    public IReadOnlyList<Finding> ScanTargets(IReadOnlyList<WebAppTarget> targets, string rulesPath)
    {
        if (targets is null)
        {
            throw new ArgumentNullException(nameof(targets));
        }

        var findings = new List<Finding>();
        var ruleSet = _ruleLoader.Load(rulesPath);

        foreach (var target in targets)
        {
            foreach (var configFile in target.ConfigFiles)
            {
                if (!File.Exists(configFile))
                {
                    continue;
                }

                var content = File.ReadAllText(configFile);

                var configFindings = _textEvidenceScanner.ScanText(
                    content,
                    "config",
                    configFile,
                    string.Empty,
                    target.SiteName,
                    target.ApplicationPath,
                    target.PhysicalPath,
                    ruleSet);

                findings.AddRange(configFindings);

                var configEntropyFindings = _entropyEvidenceScanner.ScanText(
                    content,
                    "config",
                    configFile,
                    string.Empty,
                    target.SiteName,
                    target.ApplicationPath,
                    target.PhysicalPath);

                findings.AddRange(configEntropyFindings);
            }

            foreach (var assemblyPath in target.AssemblyPaths)
            {
                if (!File.Exists(assemblyPath))
                {
                    continue;
                }

                string binaryStrings;

                try
                {
                    binaryStrings = _binaryStringExtractor.ExtractStrings(assemblyPath);
                }
                catch
                {
                    binaryStrings = string.Empty;
                }

                if (!string.IsNullOrWhiteSpace(binaryStrings))
                {
                    var binaryFindings = _textEvidenceScanner.ScanText(
                        binaryStrings,
                        "binary-strings",
                        assemblyPath,
                        assemblyPath,
                        target.SiteName,
                        target.ApplicationPath,
                        target.PhysicalPath,
                        ruleSet);

                    findings.AddRange(binaryFindings);

                    var binaryEntropyFindings = _entropyEvidenceScanner.ScanText(
                        binaryStrings,
                        "binary-strings",
                        assemblyPath,
                        assemblyPath,
                        target.SiteName,
                        target.ApplicationPath,
                        target.PhysicalPath);

                    findings.AddRange(binaryEntropyFindings);
                }

                string managedStrings;

                try
                {
                    managedStrings = _managedStringExtractor.ExtractStrings(assemblyPath);
                }
                catch
                {
                    managedStrings = string.Empty;
                }

                if (!string.IsNullOrWhiteSpace(managedStrings))
                {
                    var managedFindings = _textEvidenceScanner.ScanText(
                        managedStrings,
                        "managed-strings",
                        assemblyPath,
                        assemblyPath,
                        target.SiteName,
                        target.ApplicationPath,
                        target.PhysicalPath,
                        ruleSet);

                    findings.AddRange(managedFindings);

                    var managedEntropyFindings = _entropyEvidenceScanner.ScanText(
                        managedStrings,
                        "managed-strings",
                        assemblyPath,
                        assemblyPath,
                        target.SiteName,
                        target.ApplicationPath,
                        target.PhysicalPath);

                    findings.AddRange(managedEntropyFindings);
                }

                string decompiledText;

                try
                {
                    decompiledText = _decompilerAdapter.DecompileAssembly(assemblyPath);
                }
                catch
                {
                    continue;
                }

                var assemblyFindings = _textEvidenceScanner.ScanText(
                    decompiledText,
                    "decompiled",
                    assemblyPath,
                    assemblyPath,
                    target.SiteName,
                    target.ApplicationPath,
                    target.PhysicalPath,
                    ruleSet);

                findings.AddRange(assemblyFindings);

                var decompiledEntropyFindings = _entropyEvidenceScanner.ScanText(
                    decompiledText,
                    "decompiled",
                    assemblyPath,
                    assemblyPath,
                    target.SiteName,
                    target.ApplicationPath,
                    target.PhysicalPath);

                findings.AddRange(decompiledEntropyFindings);
            }
        }

        return DeduplicateFindings(findings);
    }

    private static IReadOnlyList<Finding> DeduplicateFindings(List<Finding> findings)
{
    var nonEntropyKeys = new HashSet<string>(
        findings
            .Where(f => !string.Equals(f.RuleId, "high-entropy-candidate", StringComparison.OrdinalIgnoreCase))
            .Select(f => BuildFindingKey(f)),
        StringComparer.OrdinalIgnoreCase);

    var filtered = findings
        .Where(f =>
        {
            if (!string.Equals(f.RuleId, "high-entropy-candidate", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return !nonEntropyKeys.Contains(BuildFindingKey(f));
        })
        .ToList();

    return filtered
        .GroupBy(f => new
        {
            f.RuleId,
            f.MatchedValue,
            f.FilePath
        })
        .Select(g => g.First())
        .ToList();
}

private static string BuildFindingKey(Finding finding)
{
    return $"{finding.FilePath}|{finding.MatchedValue}";
}
}