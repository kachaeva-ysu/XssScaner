using System.Text;
using System.Text.RegularExpressions;

namespace Xss
{
    public class ContentHelper
    {
        public static async Task<string> GetContent(string url, List<KeyValuePair<string, string>>? data = null)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0");

            var response = data == null ?
                await httpClient.GetAsync(url) :
                await httpClient.PostAsync(url, new FormUrlEncodedContent(data));

            return await response.Content.ReadAsStringAsync();
        }

        public static List<KeyValuePair<string, string>> GetUrlParameters(string url)
        {
            url = url.IndexOf("?") != -1 ? url.Substring(url.IndexOf("?") + 1) : string.Empty;
            var nameValues = !string.IsNullOrEmpty(url) ? url.Split(new char[] { '&', '=' }, StringSplitOptions.RemoveEmptyEntries) : Array.Empty<string>();
            var parameters = new List<KeyValuePair<string, string>>();

            for (var i = 0; i < nameValues.Length; i += 2)
                parameters.Add(new KeyValuePair<string, string>(nameValues[i], nameValues[i + 1]));

            return parameters;
        }

        public static List<KeyValuePair<string, string>> GetDataParameters(string content)
        {
            var regex = @"<input.*?name=(""|')(.*?)(""|')";
            var matches = Regex.Matches(content, regex, RegexOptions.IgnoreCase);
            var names = (matches.Select(match => match.Groups[2].ToString())).ToList();
            var parameters = new List<KeyValuePair<string, string>>();

            foreach (var name in names)
                parameters.Add(new KeyValuePair<string, string>(name, string.Empty));

            return parameters;
        }
    }
}
