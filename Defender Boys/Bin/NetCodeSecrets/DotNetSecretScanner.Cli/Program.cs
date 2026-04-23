using DotNetSecretScanner.Cli.Decompilation;
using DotNetSecretScanner.Cli.Discovery;
using DotNetSecretScanner.Cli.Evidence;
using DotNetSecretScanner.Cli.Models;
using DotNetSecretScanner.Cli.Reporting;
using DotNetSecretScanner.Cli.Scanner;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        var command = args[0].ToLowerInvariant();

        if (command == "aggregate")
        {
            return RunAggregate(args);
        }

        if (command == "scan")
        {
            return RunScan(args);
        }

        if (command == "remote-scan")
        {
            return RunRemoteScan(args);
        }

        PrintUsage();
        return 1;
    }

    private static int RunAggregate(string[] args)
    {
        string inputFolder = null!;
        string outputFile = "combined.html";

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--input" && i + 1 < args.Length)
            {
                inputFolder = args[++i];
            }
            else if (args[i] == "--out" && i + 1 < args.Length)
            {
                outputFile = args[++i];
            }
        }

        if (string.IsNullOrWhiteSpace(inputFolder))
        {
            Console.WriteLine("Missing required parameter: --input <folder>");
            return 1;
        }

        var loader = new JsonFindingCollectionLoader();
        var findings = loader.LoadFromFolder(inputFolder);

        if (findings.Count == 0)
        {
            Console.WriteLine("No findings found in input folder.");
            return 1;
        }

        var writer = new HtmlReportWriter();
        writer.Write(outputFile, findings);

        Console.WriteLine($"Aggregate report written to: {outputFile}");
        Console.WriteLine($"Total findings: {findings.Count}");
        return 0;
    }
    private static int RunScan(string[] args)
    {
        if (args.Length != 4)
        {
            PrintUsage();
            return 1;
        }

        var appDiscovery = new FilesystemAppDiscovery();
        var iisAppDiscovery = new IisAppDiscovery();
        var ruleLoader = new JsonRuleLoader();
        var textEvidenceScanner = new RegexTextEvidenceScanner();
        var entropyDetector = new ShannonEntropyDetector();
        var entropyEvidenceScanner = new EntropyEvidenceScanner(entropyDetector);
        var decompilerAdapter = new IlSpyDecompilerAdapter();
        var binaryStringExtractor = new BinaryStringExtractor();
        var managedStringExtractor = new ManagedStringExtractor();
        var orchestrator = new ScanOrchestrator(
            appDiscovery,
            ruleLoader,
            textEvidenceScanner,
            entropyEvidenceScanner,
            decompilerAdapter,
            binaryStringExtractor,
            managedStringExtractor);
        var jsonReportWriter = new JsonReportWriter();
        var htmlReportWriter = new HtmlReportWriter();

        if (string.Equals(args[1], "--iis", StringComparison.OrdinalIgnoreCase))
        {
            var rulesPath = args[2];
            var outputPath = args[3];

            try
            {
                var targets = iisAppDiscovery.Discover();
                var findings = orchestrator.ScanTargets(targets, rulesPath);

                jsonReportWriter.Write(outputPath, findings);

                var htmlOutputPath = Path.ChangeExtension(outputPath, ".html");
                htmlReportWriter.Write(htmlOutputPath, findings);

                Console.WriteLine($"Scan complete. Findings: {findings.Count}");
                Console.WriteLine($"JSON report written to: {outputPath}");
                Console.WriteLine($"HTML report written to: {htmlOutputPath}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"IIS discovery error: {ex.Message}");
                return 3;
            }
        }

        try
        {
            var rootPath = args[1];
            var rulesPath = args[2];
            var outputPath = args[3];

            var findings = orchestrator.Scan(rootPath, rulesPath);

            jsonReportWriter.Write(outputPath, findings);

            var htmlOutputPath = Path.ChangeExtension(outputPath, ".html");
            htmlReportWriter.Write(htmlOutputPath, findings);

            Console.WriteLine($"Scan complete. Findings: {findings.Count}");
            Console.WriteLine($"JSON report written to: {outputPath}");
            Console.WriteLine($"HTML report written to: {htmlOutputPath}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return 2;
        }
    }
    
        private static int RunRemoteScan(string[] args)
    {
        string targetsPath = null!;
        string exePath = null!;
        string rulesPath = null!;
        string collectFolder = null!;
        string remotePath = string.Empty;
        string aggregateOutput = string.Empty;

        var useIis = false;
        var maxParallelism = 5;
        var cleanup = false;

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--targets" && i + 1 < args.Length)
            {
                targetsPath = args[++i];
            }
            else if (args[i] == "--exe" && i + 1 < args.Length)
            {
                exePath = args[++i];
            }
            else if (args[i] == "--rules" && i + 1 < args.Length)
            {
                rulesPath = args[++i];
            }
            else if (args[i] == "--collect" && i + 1 < args.Length)
            {
                collectFolder = args[++i];
            }
            else if (args[i] == "--iis")
            {
                useIis = true;
            }
            else if (args[i] == "--path" && i + 1 < args.Length)
            {
                remotePath = args[++i];
            }
            else if (args[i] == "--parallel" && i + 1 < args.Length)
            {
                if (!int.TryParse(args[++i], out maxParallelism) || maxParallelism < 1)
                {
                    Console.WriteLine("Invalid value for --parallel. Use an integer >= 1.");
                    return 1;
                }
            }
            else if (args[i] == "--cleanup")
            {
                cleanup = true;
            }
            else if (args[i] == "--aggregate" && i + 1 < args.Length)
            {
                aggregateOutput = args[++i];
            }
        }

        if (string.IsNullOrWhiteSpace(targetsPath))
        {
            Console.WriteLine("Missing required parameter: --targets <file>");
            return 1;
        }

        if (string.IsNullOrWhiteSpace(exePath))
        {
            Console.WriteLine("Missing required parameter: --exe <path>");
            return 1;
        }

        if (string.IsNullOrWhiteSpace(rulesPath))
        {
            Console.WriteLine("Missing required parameter: --rules <path>");
            return 1;
        }

        if (string.IsNullOrWhiteSpace(collectFolder))
        {
            Console.WriteLine("Missing required parameter: --collect <folder>");
            return 1;
        }

        if (!useIis && string.IsNullOrWhiteSpace(remotePath))
        {
            Console.WriteLine("Specify either --iis or --path <remoteFolder>.");
            return 1;
        }

        try
        {
            var loader = new RemoteTargetListLoader();
            var targets = loader.LoadFromFile(targetsPath);

            if (targets.Count == 0)
            {
                Console.WriteLine("No remote targets found.");
                return 1;
            }

            var options = new RemoteExecutionOptions
            {
                LocalExecutablePath = exePath,
                LocalRulesPath = rulesPath,
                LocalCollectFolderPath = collectFolder,
                UseIisDiscovery = useIis,
                RemoteScanPath = remotePath,
                MaxParallelism = maxParallelism,
                CleanupRemoteFiles = cleanup,
                AggregateOutputPath = aggregateOutput
            };

            var executor = new PowerShellRemoteScanExecutor();
            executor.ExecuteScans(targets, options);

            Console.WriteLine($"Remote scan complete. Collected results in: {Path.GetFullPath(collectFolder)}");

            // Auto-aggregate
            if (!string.IsNullOrWhiteSpace(aggregateOutput))
            {
                Console.WriteLine("[+] Building aggregate report...");

                var loader2 = new JsonFindingCollectionLoader();
                var findings = loader2.LoadFromFolder(collectFolder);

                if (findings.Count == 0)
                {
                    Console.WriteLine("[!] No findings to aggregate.");
                    return 1;
                }

                var writer = new HtmlReportWriter();
                writer.Write(aggregateOutput, findings);

                Console.WriteLine($"[+] Aggregate report written to: {aggregateOutput}");
                Console.WriteLine($"[+] Total findings: {findings.Count}");
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Remote scan error: {ex.Message}");
            return 2;
        }
    }

        private static void PrintUsage()
    {
        Console.WriteLine("Defender Boys - NetSecretScan");
        Console.WriteLine("Version: 1.0\n");

        Console.WriteLine("Commands:");
        Console.WriteLine("  scan           Scan local files or IIS content");
        Console.WriteLine("  aggregate      Generate HTML report from scan results");
        Console.WriteLine("  remote-scan    Execute scan on remote targets\n");

        Console.WriteLine("Arguments:");

        Console.WriteLine("  scan:");
        Console.WriteLine("    <path>               Local folder to scan");
        Console.WriteLine("    --iis                Scan IIS content");
        Console.WriteLine("    <rules.json>         Detection rules");
        Console.WriteLine("    <output.json>        Output file\n");

        Console.WriteLine("  aggregate:");
        Console.WriteLine("    --input <folder>     Folder with scan results");
        Console.WriteLine("    --out <report.html>  Output report\n");

        Console.WriteLine("  remote-scan:");
        Console.WriteLine("    --targets <file>     List of target hosts");
        Console.WriteLine("    --exe <path>         Scanner executable");
        Console.WriteLine("    --rules <path>       Rules file");
        Console.WriteLine("    --collect <folder>   Output collection folder");
        Console.WriteLine("    --path <folder>      Remote folder to scan");
        Console.WriteLine("    --iis                Scan IIS content");
        Console.WriteLine("    --parallel <n>       Number of concurrent scans");
        Console.WriteLine("    --cleanup            Remove remote artifacts after scan");
        Console.WriteLine("    --aggregate <html>   Generate combined report\n");

        Console.WriteLine("Examples:");
        Console.WriteLine("  NetCodeSecrets scan C:\\inetpub\\wwwroot rules.json output.json");
        Console.WriteLine("  NetCodeSecrets scan --iis rules.json output.json");
        Console.WriteLine("  NetCodeSecrets remote-scan --targets hosts.txt --exe scanner.exe --rules rules.json --collect results --iis --parallel 10 --cleanup");
    }
}