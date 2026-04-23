using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Reporting;

public interface IRemoteScanExecutor
{
    void ExecuteScans(
        IReadOnlyList<RemoteScanTarget> targets,
        string rulesPath,
        string collectFolderPath);
}