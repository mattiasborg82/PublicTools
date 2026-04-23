namespace DotNetSecretScanner.Cli.Decompilation;

public interface IDecompilerAdapter
{
    string DecompileAssembly(string assemblyPath);
}