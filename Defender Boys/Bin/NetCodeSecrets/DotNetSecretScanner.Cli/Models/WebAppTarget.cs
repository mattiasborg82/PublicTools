namespace DotNetSecretScanner.Cli.Models;

public sealed class WebAppTarget
{
    public string HostName { get; set; } = string.Empty;

    public string SiteName { get; set; } = string.Empty;

    public string ApplicationPath { get; set; } = string.Empty;

    public string PhysicalPath { get; set; } = string.Empty;

    public string AppPoolName { get; set; } = string.Empty;

    public bool IsAspNetCoreStyle { get; set; }

    public List<string> AssemblyPaths { get; set; } = new();

    public List<string> ConfigFiles { get; set; } = new();
}