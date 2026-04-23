namespace DotNetSecretScanner.Cli.Models;

public sealed class RemoteExecutionOptions
{
    public string LocalExecutablePath { get; set; } = string.Empty;

    public string LocalRulesPath { get; set; } = string.Empty;

    public string LocalCollectFolderPath { get; set; } = string.Empty;

    public string RemoteWorkingFolderPath { get; set; } = @"C:\Windows\Temp\NetCodeSecrets";

    public bool UseIisDiscovery { get; set; }

    public string RemoteScanPath { get; set; } = string.Empty;

    public int MaxParallelism { get; set; } = 5;

    public bool CleanupRemoteFiles { get; set; }

    public string AggregateOutputPath { get; set; } = string.Empty;
}