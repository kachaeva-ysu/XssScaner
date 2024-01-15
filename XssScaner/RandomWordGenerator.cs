using System.Text;

namespace Xss
{
    public static class RandomWordGenerator
    {
        public static string GenerateRandomWord(int length)
        {
            var random = new Random();
            var result = new StringBuilder();

            for (var i = 0; i < length; i++)
                result.Append((char)random.Next(0x061, 0x07A));

            return result.ToString();
        }
    }
}
