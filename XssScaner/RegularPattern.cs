namespace Xss
{
    public class RegularPattern
    {
        public string Regex { get; set; }

        public string Info { get; set; }

        public char[] Condition { get; set; }

        public string RemovalRegex { get; set; }

        public static List<RegularPattern> GetRegularPatterns()
        {
            var regularPatterns = new List<RegularPattern>
            {
                new RegularPattern
                {
                    Regex = @"(?s)<script[^>]*>[^<]*?'[^<']*match[^<']*'[^<]*</script>",
                    Condition = new[] { '\'', ';' },
                    Info = "enclosed by <script> tags, inside single-quotes, no ' and ; filtering",
                    RemovalRegex = @"\\'|{[^\n]+}"
                },

                new RegularPattern
                {
                    Regex = @"(?s)<script[^>]*>[^<]*?""[^<""]*match[^<""]*""[^<]*</script>",
                    Condition = new[] { '"', ';' },
                    Info = "enclosed by <script> tags, inside double-quotes, no \" and ; filtering",
                    RemovalRegex = @"\\""|{[^\n]+}"
                },

                new RegularPattern
                {
                    Regex = @"(?s)<script[^>]*>[^<]*?match[^<]*</script>",
                    Condition = new[] { ';' },
                    Info = "enclosed by <script> tags, outside quotes, no ; filtering",
                    RemovalRegex = @"'[^'\s]+'|\""[^\""\s]+\""|{[^\n]+}"
                },

                new RegularPattern
                {
                    Regex = @"<[^>]*=\s*'[^>']*match[^>']*'[^>]*>",
                    Condition = new[] { '\'' },
                    Info = "inside the tag, inside single quotes, no ' filtering",
                },

                new RegularPattern
                {
                    Regex = @"<[^>]*=\s*""[^>""]*match[^>""]*""[^>]*>",
                    Condition = new[] { '"' },
                    Info = "inside the tag, inside double quotes, no \" filtering",
                },

                new RegularPattern
                {
                    Regex = @"<[^>]*match[^>]*>",
                    Condition = Array.Empty<char>(),
                    Info = "inside the tag, outside of quotes",
                },

                new RegularPattern
                {
                    Regex = @"<!--[^>]*match[^>]*-->",
                    Condition = new[] { '<', '>' },
                    Info = "inside the comment, no < and > filtering"
                },

                new RegularPattern
                {
                    Regex = @">[^<]*match[^<]*(<|\Z)",
                    Condition = new[] { '<', '>' },
                    Info = "outside of tag, no < and > filtering",
                }
            };

            return regularPatterns;
        }
    }
}
