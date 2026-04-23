# NetCodeSecrets

NetCodeSecrets is a .NET secret discovery tool for web apps and IIS servers.

Rules json file is located in the DotNetSecretScanner.Cli\rules

It uses ICSharpCode.Decompiler for .NET assembly decompilation.

You can use the test app /TestFakeSecrets for testing


```cmd
dotnet build
```
or 
```cmd
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

### LocalTest

```cmd
NetCodeSecrets.exe scan TestApp evidence-rules.json output.json
```


## What it does

- Scans config files and assemblies for secrets
- Supports regex-based detections and entropy-based detections
- Scans local paths or IIS-discovered applications
- Runs remotely against multiple hosts
- Generates JSON and HTML reports
- Aggregates per-host JSON into a combined HTML dashboard

## Main features

- Local scan
- IIS scan
- Remote scan with:
  - parallel execution
  - optional cleanup
  - IIS or path mode
- Aggregate reporting
- Host dashboard
- Search and click-to-filter in HTML
- Confidence field for findings

## Commands

### Scan a local path

```cmd
NetCodeSecrets scan <path> <rules.json> <output.json>
```

### Scan IIS on the local machine

```cmd
NetCodeSecrets scan --iis <rules.json> <output.json>
```

### Aggregate JSON reports into one HTML report

```cmd
NetCodeSecrets aggregate --input <folder> --out <report.html>
```

### Remote scan using IIS discovery

```cmd
NetCodeSecrets remote-scan --targets <file> --exe <path> --rules <path> --collect <folder> --iis [--parallel <n>] [--cleanup] [--aggregate <html>]
```

### Remote scan using a specific remote path

```cmd
NetCodeSecrets remote-scan --targets <file> --exe <path> --rules <path> --collect <folder> --path <remoteFolder> [--parallel <n>] [--cleanup] [--aggregate <html>]
```

## Example workflow

```cmd
NetCodeSecrets remote-scan --targets .\servers.txt --exe .\NetCodeSecrets.exe --rules .\evidence-rules.json --collect .\reports --iis --parallel 5 --cleanup --aggregate .\combined.html
```

## Output

- `*.json` - raw findings
- `*.html` - analyst-friendly report

## Notes

- Remote scan copies the EXE and rules to the remote host, runs locally there, collects JSON back, and can remove remote files afterward.
- Confidence is typically:
  - `high` for rule-based detections
  - `medium` for entropy findings

## Author

Defender Boys

## Reach out
Feel free to reach out with comments, feedback etc