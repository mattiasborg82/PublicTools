using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Reporting;

public sealed class RemoteTargetListLoader
{
    public IReadOnlyList<RemoteScanTarget> LoadFromFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Target list path must not be empty.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Target list file was not found.", fullPath);
        }

        var results = new List<RemoteScanTarget>();
        var lines = File.ReadAllLines(fullPath);

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            results.Add(new RemoteScanTarget
            {
                ComputerName = line
            });
        }

        return results;
    }
}