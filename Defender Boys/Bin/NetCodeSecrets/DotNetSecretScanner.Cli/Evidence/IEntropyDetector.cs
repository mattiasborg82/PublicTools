namespace DotNetSecretScanner.Cli.Evidence;

public interface IEntropyDetector
{
    bool IsHighEntropyCandidate(string value);
}