namespace SecretTestLib;

public class Class1
{
    public string GetConnectionString()
    {
        return "Server=db02;Database=Prod;User Id=svc_code;Password=CodeSecret456!;";
    }

    public string GetBearerToken()
    {
        return "Bearer codebasedtoken123456789";
    }
}