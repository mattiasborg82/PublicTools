using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Discovery;

public interface IAppDiscovery
{
    IReadOnlyList<WebAppTarget> Discover(string rootPath);
}