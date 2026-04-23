using System.Diagnostics;
using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Reporting;

public sealed class PowerShellRemoteScanExecutor : IRemoteScanExecutor
{
    private static readonly object ConsoleLock = new();

    public void ExecuteScans(
        IReadOnlyList<RemoteScanTarget> targets,
        string rulesPath,
        string collectFolderPath)
    {
        throw new NotSupportedException("Use ExecuteScans with RemoteExecutionOptions.");
    }

    public void ExecuteScans(
        IReadOnlyList<RemoteScanTarget> targets,
        RemoteExecutionOptions options)
    {
        if (targets is null || targets.Count == 0)
        {
            throw new ArgumentException("No targets provided.", nameof(targets));
        }

        if (!options.UseIisDiscovery && string.IsNullOrWhiteSpace(options.RemoteScanPath))
        {
            throw new ArgumentException("RemoteScanPath must be provided when IIS discovery is not enabled.", nameof(options));
        }

        if (options.MaxParallelism < 1)
        {
            throw new ArgumentException("MaxParallelism must be at least 1.", nameof(options));
        }

        Directory.CreateDirectory(options.LocalCollectFolderPath);

        var exeFullPath = Path.GetFullPath(options.LocalExecutablePath);
        var rulesFullPath = Path.GetFullPath(options.LocalRulesPath);

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = options.MaxParallelism
        };

        Parallel.ForEach(targets, parallelOptions, target =>
        {
            Log($"[+] Processing {target.ComputerName}");

            try
            {
                StageFiles(target, exeFullPath, rulesFullPath, options);
                ExecuteRemoteScan(target, options);
                CollectResults(target, options);

                if (options.CleanupRemoteFiles)
                {
                    CleanupRemoteFiles(target, options);
                }

                Log($"[+] Completed {target.ComputerName}");
            }
            catch (Exception ex)
            {
                Log($"[!] Failed on {target.ComputerName}: {ex.Message}");
            }
        });
    }

    private void StageFiles(
        RemoteScanTarget target,
        string exePath,
        string rulesPath,
        RemoteExecutionOptions options)
    {
        var remoteBase = $@"\\{target.ComputerName}\C$\Windows\Temp\NetCodeSecrets";

        Log($"    [{target.ComputerName}] Creating remote folder");
        Directory.CreateDirectory(remoteBase);

        Log($"    [{target.ComputerName}] Copying EXE");
        File.Copy(exePath, Path.Combine(remoteBase, "NetCodeSecrets.exe"), true);

        Log($"    [{target.ComputerName}] Copying rules");
        File.Copy(rulesPath, Path.Combine(remoteBase, "rules.json"), true);
    }

    private void ExecuteRemoteScan(RemoteScanTarget target, RemoteExecutionOptions options)
    {
        Log($"    [{target.ComputerName}] Executing scan via Invoke-Command");

        var remoteCommand = BuildRemoteScanCommand(options);

        var command = $@"
Invoke-Command -ComputerName {target.ComputerName} -ScriptBlock {{
    Set-Location '{options.RemoteWorkingFolderPath}'
    {remoteCommand}
}}
";

        RunPowerShell(command, target.ComputerName);
    }

    private static string BuildRemoteScanCommand(RemoteExecutionOptions options)
    {
        if (options.UseIisDiscovery)
        {
            return @".\NetCodeSecrets.exe scan --iis rules.json output.json";
        }

        var escapedPath = EscapePowerShellSingleQuotedString(options.RemoteScanPath);
        return $@".\NetCodeSecrets.exe scan '{escapedPath}' rules.json output.json";
    }

    private void CollectResults(RemoteScanTarget target, RemoteExecutionOptions options)
    {
        Log($"    [{target.ComputerName}] Collecting results");

        var remoteFile = $@"\\{target.ComputerName}\C$\Windows\Temp\NetCodeSecrets\output.json";
        var localFile = Path.Combine(options.LocalCollectFolderPath, $"{target.ComputerName}.json");

        if (!File.Exists(remoteFile))
        {
            throw new Exception("Remote output.json not found.");
        }

        File.Copy(remoteFile, localFile, true);
    }

    private void CleanupRemoteFiles(RemoteScanTarget target, RemoteExecutionOptions options)
    {
        Log($"    [{target.ComputerName}] Cleaning up remote files");

        var command = $@"
Invoke-Command -ComputerName {target.ComputerName} -ScriptBlock {{
    if (Test-Path '{options.RemoteWorkingFolderPath}') {{
        Remove-Item -Path '{options.RemoteWorkingFolderPath}' -Recurse -Force -ErrorAction Stop
    }}
}}
";

        RunPowerShell(command, target.ComputerName);
    }

    private static void RunPowerShell(string command, string computerName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var process = Process.Start(psi);

        var stdout = process!.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();

        process.WaitForExit();

        if (!string.IsNullOrWhiteSpace(stdout))
        {
            Log($"    [{computerName}] STDOUT:");
            Log(stdout.TrimEnd());
        }

        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Log($"    [{computerName}] STDERR:");
            Log(stderr.TrimEnd());
        }
    }

    private static string EscapePowerShellSingleQuotedString(string value)
    {
        return (value ?? string.Empty).Replace("'", "''", StringComparison.Ordinal);
    }

    private static void Log(string message)
    {
        lock (ConsoleLock)
        {
            Console.WriteLine(message);
        }
    }
}