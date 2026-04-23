using DotNetSecretScanner.Cli.Models;
using Microsoft.Web.Administration;

namespace DotNetSecretScanner.Cli.Discovery;

public sealed class IisAppDiscovery : IIisAppDiscovery
{
    public IReadOnlyList<WebAppTarget> Discover()
    {
        var results = new List<WebAppTarget>();

        try
        {
            using var serverManager = new ServerManager();

            foreach (var site in serverManager.Sites)
            {
                foreach (var application in site.Applications)
                {
                    foreach (var virtualDirectory in application.VirtualDirectories)
                    {
                        var rawPhysicalPath = virtualDirectory.PhysicalPath;

                        if (string.IsNullOrWhiteSpace(rawPhysicalPath))
                        {
                            continue;
                        }

                        var physicalPath = Environment.ExpandEnvironmentVariables(rawPhysicalPath);
                        physicalPath = Path.GetFullPath(physicalPath);

                        if (!Directory.Exists(physicalPath))
                        {
                            continue;
                        }

                        var target = new WebAppTarget
                        {
                            HostName = Environment.MachineName,
                            SiteName = site.Name,
                            ApplicationPath = application.Path,
                            PhysicalPath = physicalPath,
                            AppPoolName = application.ApplicationPoolName,
                            IsAspNetCoreStyle = File.Exists(Path.Combine(physicalPath, "appsettings.json"))
                        };

                        var webConfigPath = Path.Combine(physicalPath, "web.config");
                        if (File.Exists(webConfigPath))
                        {
                            target.ConfigFiles.Add(Path.GetFullPath(webConfigPath));
                        }

                        var appSettingsFiles = Directory.GetFiles(physicalPath, "appsettings*.json", SearchOption.TopDirectoryOnly)
                            .Select(Path.GetFullPath);
                        target.ConfigFiles.AddRange(appSettingsFiles);

                        var binPath = Path.Combine(physicalPath, "bin");
                        if (Directory.Exists(binPath))
                        {
                            var dllFiles = Directory.GetFiles(binPath, "*.dll", SearchOption.TopDirectoryOnly)
                                .Select(Path.GetFullPath);
                            target.AssemblyPaths.AddRange(dllFiles);
                        }

                        var rootDllFiles = Directory.GetFiles(physicalPath, "*.dll", SearchOption.TopDirectoryOnly)
                            .Select(Path.GetFullPath);
                        target.AssemblyPaths.AddRange(rootDllFiles);

                        results.Add(target);
                    }
                }
            }

            return results;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "IIS discovery is unavailable on this machine. IIS may not be installed, or the IIS administration components may be missing.",
                ex);
        }
    }
}