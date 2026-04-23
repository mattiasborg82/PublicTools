using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;

namespace DotNetSecretScanner.Cli.Decompilation;

public sealed class IlSpyDecompilerAdapter : IDecompilerAdapter
{
    public string DecompileAssembly(string assemblyPath)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath))
        {
            throw new ArgumentException("Assembly path must not be empty.", nameof(assemblyPath));
        }

        if (!File.Exists(assemblyPath))
        {
            throw new FileNotFoundException("Assembly file was not found.", assemblyPath);
        }

        var settings = new DecompilerSettings();
        var decompiler = new CSharpDecompiler(assemblyPath, settings);
        return decompiler.DecompileWholeModuleAsString();
    }
}