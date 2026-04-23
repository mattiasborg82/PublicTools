using System.Text.Json;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Reporting;

public sealed class JsonFindingCollectionLoader
{
    public IReadOnlyList<Finding> LoadFromFolder(string folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath))
        {
            throw new ArgumentException("Input folder path must not be empty.", nameof(folderPath));
        }

        var fullFolderPath = Path.GetFullPath(folderPath);

        if (!Directory.Exists(fullFolderPath))
        {
            throw new DirectoryNotFoundException($"Input folder was not found: {fullFolderPath}");
        }

        var findings = new List<Finding>();
        var jsonFiles = Directory.GetFiles(fullFolderPath, "*.json", SearchOption.TopDirectoryOnly);

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        foreach (var jsonFile in jsonFiles)
        {
            var json = File.ReadAllText(jsonFile);
            var fileFindings = JsonSerializer.Deserialize<List<Finding>>(json, options);

            if (fileFindings is null)
            {
                continue;
            }

            findings.AddRange(fileFindings);
        }

        return DeduplicateFindings(findings);
    }

    private static IReadOnlyList<Finding> DeduplicateFindings(List<Finding> findings)
    {
        return findings
            .GroupBy(f => new
            {
                HostName = f.HostName ?? string.Empty,
                FilePath = f.FilePath ?? string.Empty,
                RuleId = f.RuleId ?? string.Empty,
                MatchedValue = f.MatchedValue ?? string.Empty
            })
            .Select(g => g.First())
            .ToList();
    }
}