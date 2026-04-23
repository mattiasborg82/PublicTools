using System.Text;

namespace DotNetSecretScanner.Cli.Scanner;

public sealed class BinaryStringExtractor : IBinaryStringExtractor
{
    public string ExtractStrings(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("File path must not be empty.", nameof(filePath));
        }

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("Binary file was not found.", filePath);
        }

        var bytes = File.ReadAllBytes(filePath);
        var result = new StringBuilder();

        ExtractAsciiStrings(bytes, result);
        ExtractUtf16LeStrings(bytes, result);

        return result.ToString();
    }

    private static void ExtractAsciiStrings(byte[] bytes, StringBuilder result)
    {
        var current = new StringBuilder();

        foreach (var value in bytes)
        {
            if (value >= 32 && value <= 126)
            {
                current.Append((char)value);
            }
            else
            {
                FlushCurrentString(current, result);
            }
        }

        FlushCurrentString(current, result);
    }

    private static void ExtractUtf16LeStrings(byte[] bytes, StringBuilder result)
    {
        var current = new StringBuilder();

        for (var i = 0; i < bytes.Length - 1; i += 2)
        {
            var low = bytes[i];
            var high = bytes[i + 1];

            if (high == 0 && low >= 32 && low <= 126)
            {
                current.Append((char)low);
            }
            else
            {
                FlushCurrentString(current, result);
            }
        }

        FlushCurrentString(current, result);
    }

    private static void FlushCurrentString(StringBuilder current, StringBuilder result)
    {
        if (current.Length >= 8)
        {
            result.AppendLine(current.ToString());
        }

        current.Clear();
    }
}