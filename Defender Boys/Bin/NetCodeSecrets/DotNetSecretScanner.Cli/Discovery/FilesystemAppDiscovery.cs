using DotNetSecretScanner.Cli.Models;

namespace DotNetSecretScanner.Cli.Discovery;

public sealed class FilesystemAppDiscovery : IAppDiscovery
{
    public IReadOnlyList<WebAppTarget> Discover(string rootPath)
    {
        var results = new List<WebAppTarget>();

        if (string.IsNullOrWhiteSpace(rootPath))
        {
            return results;
        }

        var fullRootPath = Path.GetFullPath(rootPath);

        if (!Directory.Exists(fullRootPath))
        {
            return results;
        }

        AddTargetIfWebApp(fullRootPath, results);

        var directories = Directory.GetDirectories(fullRootPath);

        foreach (var directory in directories)
        {
            var directoryName = Path.GetFileName(directory);

            if (string.Equals(directoryName, "bin", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            AddTargetIfWebApp(directory, results);
        }

        return results;
    }

    private static void AddTargetIfWebApp(string directory, List<WebAppTarget> results)
    {
        var fullDirectory = Path.GetFullPath(directory);

        var webConfigPath = Path.Combine(fullDirectory, "web.config");
        var hasWebConfig = File.Exists(webConfigPath);

        var binPath = Path.Combine(fullDirectory, "bin");
        var hasBinDirectory = Directory.Exists(binPath);

        var rootDllFiles = Directory.GetFiles(fullDirectory, "*.dll", SearchOption.TopDirectoryOnly);
        var hasRootDlls = rootDllFiles.Length > 0;

        if (!hasWebConfig && !hasBinDirectory && !hasRootDlls)
        {
            return;
        }

        var target = new WebAppTarget
        {
            HostName = Environment.MachineName,
            SiteName = Path.GetFileName(fullDirectory),
            ApplicationPath = "/",
            PhysicalPath = fullDirectory,
            AppPoolName = string.Empty,
            IsAspNetCoreStyle = File.Exists(Path.Combine(fullDirectory, "appsettings.json"))
        };

        if (hasBinDirectory)
        {
            var dllFiles = Directory.GetFiles(binPath, "*.dll", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFullPath);
            target.AssemblyPaths.AddRange(dllFiles);
        }

        if (hasRootDlls)
        {
            target.AssemblyPaths.AddRange(rootDllFiles.Select(Path.GetFullPath));
        }

        if (hasWebConfig)
        {
            target.ConfigFiles.Add(Path.GetFullPath(webConfigPath));
        }

        var appSettingsFiles = Directory.GetFiles(fullDirectory, "appsettings*.json", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFullPath);
        target.ConfigFiles.AddRange(appSettingsFiles);

        results.Add(target);
    }
}