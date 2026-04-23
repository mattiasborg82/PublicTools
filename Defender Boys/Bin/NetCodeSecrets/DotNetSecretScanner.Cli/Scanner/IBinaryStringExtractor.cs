namespace DotNetSecretScanner.Cli.Scanner;

public interface IBinaryStringExtractor
{
    string ExtractStrings(string filePath);
}