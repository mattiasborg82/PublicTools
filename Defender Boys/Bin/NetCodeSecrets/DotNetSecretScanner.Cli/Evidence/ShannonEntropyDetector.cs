using System.Text.RegularExpressions;

namespace DotNetSecretScanner.Cli.Evidence;

public sealed class ShannonEntropyDetector : IEntropyDetector
{
    private static readonly Regex AlphaOnly = new(@"^[A-Za-z]+$", RegexOptions.Compiled);
    private static readonly Regex PascalCase = new(@"^[A-Z][a-zA-Z0-9]+$", RegexOptions.Compiled);

    private static readonly string[] KnownNoisePatterns =
    [
        "Attribute",
        "System.",
        "Microsoft.",
        "Assembly",
        "Version",
        "Debug",
        "Framework"
    ];

    public bool IsHighEntropyCandidate(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var trimmed = input.Trim();
        var length = trimmed.Length;

        if (length < 20)
        {
            return false;
        }

        if (AlphaOnly.IsMatch(trimmed))
        {
            return false;
        }

        if (PascalCase.IsMatch(trimmed))
        {
            return false;
        }

        foreach (var pattern in KnownNoisePatterns)
        {
            if (trimmed.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        var entropy = CalculateEntropy(trimmed);
        return entropy >= 3.75;
    }

    private static double CalculateEntropy(string input)
    {
        var charCounts = new Dictionary<char, int>();

        foreach (var c in input)
        {
            if (!charCounts.ContainsKey(c))
            {
                charCounts[c] = 0;
            }

            charCounts[c]++;
        }

        double entropy = 0;

        foreach (var count in charCounts.Values)
        {
            double p = (double)count / input.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}