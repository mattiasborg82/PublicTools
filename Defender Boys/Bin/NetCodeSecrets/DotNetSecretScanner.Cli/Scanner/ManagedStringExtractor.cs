using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

namespace DotNetSecretScanner.Cli.Scanner;

public sealed class ManagedStringExtractor : IManagedStringExtractor
{
    public string ExtractStrings(string assemblyPath)
    {
        if (string.IsNullOrWhiteSpace(assemblyPath))
        {
            throw new ArgumentException("Assembly path must not be empty.", nameof(assemblyPath));
        }

        if (!File.Exists(assemblyPath))
        {
            throw new FileNotFoundException("Assembly file was not found.", assemblyPath);
        }

        using var stream = File.OpenRead(assemblyPath);
        using var peReader = new PEReader(stream);

        if (!peReader.HasMetadata)
        {
            return string.Empty;
        }

        var metadataReader = peReader.GetMetadataReader();
        var result = new StringBuilder();

        var handle = MetadataTokens.UserStringHandle(1);

        while (!handle.IsNil)
        {
            var value = metadataReader.GetUserString(handle);

            if (!string.IsNullOrWhiteSpace(value))
            {
                result.AppendLine(value);
            }

            handle = metadataReader.GetNextHandle(handle);
        }

        return result.ToString();
    }
}