namespace DotNetSecretScanner.Cli.Scanner;

public interface IManagedStringExtractor
{
    string ExtractStrings(string assemblyPath);
}