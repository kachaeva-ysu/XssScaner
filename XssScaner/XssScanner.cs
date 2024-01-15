using System.Text.RegularExpressions;

namespace Xss
{
    public class XssScanner
    {
        public bool IsPageXssVulnerable { get; set; }

        public async Task ScanPage(string url)
        {
            await CheckDOM(url);
            await CheckParameters(url);
        }

        private async Task CheckDOM(string url)
        {
            Console.WriteLine("Scanning for DOM Based XSS...");

            var content = await ContentHelper.GetContent(url);
            var domFilter = @"(?s)<!--.*?-->|\bescape\([^)]+\)|\bencodeURI\([^)]+\)|\bencodeURIComponent\([^)]+\)|\([^)]+==[^(]+\)|\""[^\""]+\""|'[^']+'";
            var filteredContent = Regex.Replace(content, domFilter, string.Empty);
            var domPattern = @"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>|<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>";
            var matches = Regex.Matches(filteredContent, domPattern);

            if (matches.Any())
            {
                Console.WriteLine("Found DOM Based XSS:\r\n");

                foreach (Match match in matches)
                    Console.WriteLine(match.Value + "\r\n");

                IsPageXssVulnerable = true;
            }
        }

        private async Task CheckParameters(string url)
        {
            var charPool = "'\"><;";
            var regularPatterns = RegularPattern.GetRegularPatterns();
            var content = await ContentHelper.GetContent(url);
            var urlParameters = ContentHelper.GetUrlParameters(url);
            var dataParameters = ContentHelper.GetDataParameters(content);

            foreach (var phase in new string[] { "GET", "POST" })
            {
                foreach (var parameter in phase == "GET" ? urlParameters : dataParameters)
                {
                    Console.WriteLine("Scanning " + phase + " parameter \"" + parameter.Key + "\"...");

                    var prefix = RandomWordGenerator.GenerateRandomWord(5);
                    var suffix = RandomWordGenerator.GenerateRandomWord(5);
                    var tamperedValue = prefix + charPool + suffix;
                    var tamperedUrl = phase == "GET" ? url.Replace(parameter.Value, tamperedValue) : url;
                    var tamperedData = phase == "POST" ?
                        new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>(parameter.Key, tamperedValue) } :
                        null;

                    var tamperedContent = await ContentHelper.GetContent(tamperedUrl, tamperedData);

                    foreach (var regularPattern in regularPatterns)
                    {
                        var filteredContent = regularPattern.RemovalRegex != null ?
                            Regex.Replace(tamperedContent, regularPattern.RemovalRegex, string.Empty) : tamperedContent;
                        var match = Regex.Match(filteredContent, prefix + "([^ ]+?)" + suffix);

                        if (match.Success)
                        {
                            var regex = Regex.Replace(regularPattern.Regex, "match", Regex.Escape(match.Value));
                            var context = Regex.Match(filteredContent, regex, RegexOptions.Multiline);

                            if (context.Success && regularPattern.Condition.All(x => match.Groups[1].Value.Contains(x)))
                            {
                                Console.WriteLine(phase + " parameter \"" + parameter.Key + "\" appears to be XSS vulnerable (" + regularPattern.Info + ")");
                                IsPageXssVulnerable = true;
                            }
                        }
                    }
                }
            }
        }
    }
}
