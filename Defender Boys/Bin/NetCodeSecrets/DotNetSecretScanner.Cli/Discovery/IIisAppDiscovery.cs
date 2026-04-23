using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Discovery;

public interface IIisAppDiscovery
{
    IReadOnlyList<WebAppTarget> Discover();
}