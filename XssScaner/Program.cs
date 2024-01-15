namespace Xss
{
    public class Program
    {
        private static async Task Main(string[] args)
        {
            var xssScanner = new XssScanner();
            await xssScanner.ScanPage(args[0]);
            Console.WriteLine('\n' + (xssScanner.IsPageXssVulnerable ? "Possible" : "No") + " vulnerabilities found");
        }
    }
}