using System.Text.Json;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Reporting;

public sealed class JsonReportWriter
{
    public void Write(string path, IReadOnlyList<Finding> findings)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Output path must not be empty.", nameof(path));
        }

        if (findings is null)
        {
            throw new ArgumentNullException(nameof(findings));
        }

        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(findings, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        File.WriteAllText(path, json);
    }
}