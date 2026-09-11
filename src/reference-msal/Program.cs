using System.Text;
using System.Text.Json;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

namespace AskWam.Reference.Msal;

internal static class Program
{
    private const string TeamsDesktopClientId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264";
    private const string GraphDefaultScope = "https://graph.microsoft.com/.default";

    public static async Task<int> Main(string[] args)
    {
        Options options;
        try
        {
            options = Options.Parse(args);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine();
            PrintHelp(Console.Error);
            return 2;
        }

        if (options.Help)
        {
            PrintHelp(Console.Out);
            return 0;
        }

        try
        {
            string? claims = LoadAndValidateClaims(options);
            string authority = BuildAuthority(options.Tenant);

            PublicClientApplicationBuilder builder = PublicClientApplicationBuilder
                .Create(options.ClientId)
                .WithAuthority(authority)
                .WithDefaultRedirectUri()
                .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
                {
                    ListOperatingSystemAccounts = true,
                    Title = "askWAM MSAL reference"
                });

            if (options.EnableCae)
            {
                builder = builder.WithClientCapabilities(new[] { "cp1" });
            }

            IPublicClientApplication application = builder.Build();
            AcquireTokenSilentParameterBuilder request = application.AcquireTokenSilent(
                options.Scopes,
                PublicClientApplication.OperatingSystemAccount);

            if (claims is not null)
            {
                request = request.WithClaims(claims);
            }

            AuthenticationResult result = await request.ExecuteAsync().ConfigureAwait(false);
            WriteSuccess(options, authority, result);
            return 0;
        }
        catch (MsalUiRequiredException ex)
        {
            WriteMsalError("user_interaction_required", ex);
            return 20;
        }
        catch (MsalServiceException ex)
        {
            WriteMsalError("service_error", ex);
            return 21;
        }
        catch (MsalClientException ex)
        {
            WriteMsalError("client_error", ex);
            return 22;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or JsonException)
        {
            WriteJson(new Dictionary<string, object?>
            {
                ["status"] = "input_error",
                ["errorType"] = ex.GetType().Name,
                ["message"] = ex.Message
            });
            return 2;
        }
    }

    private static string BuildAuthority(string tenant)
    {
        if (Uri.TryCreate(tenant, UriKind.Absolute, out Uri? authority))
        {
            if (!string.Equals(authority.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("The authority must use HTTPS.");
            }

            return authority.AbsoluteUri.TrimEnd('/');
        }

        return $"https://login.microsoftonline.com/{Uri.EscapeDataString(tenant)}";
    }

    private static string? LoadAndValidateClaims(Options options)
    {
        string? claims = options.ClaimsJson;
        if (options.ClaimsFile is not null)
        {
            claims = File.ReadAllText(options.ClaimsFile, Encoding.UTF8);
        }

        if (string.IsNullOrWhiteSpace(claims))
        {
            return null;
        }

        using JsonDocument document = JsonDocument.Parse(claims);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("Claims JSON must have a JSON object at its root.");
        }

        return document.RootElement.GetRawText();
    }

    private static void WriteSuccess(
        Options options,
        string authority,
        AuthenticationResult result)
    {
        var report = new Dictionary<string, object?>
        {
            ["status"] = "success",
            ["clientId"] = options.ClientId,
            ["authority"] = authority,
            ["scopesRequested"] = options.Scopes,
            ["caeCapabilityRequested"] = options.EnableCae,
            ["customClaimsRequested"] = options.ClaimsJson is not null || options.ClaimsFile is not null,
            ["tokenType"] = result.TokenType,
            ["expiresOn"] = result.ExpiresOn.ToUniversalTime().ToString("O"),
            ["correlationId"] = result.CorrelationId,
            ["claims"] = ReadSanitizedJwtClaims(result.AccessToken)
        };

        if (!options.HideToken)
        {
            report["accessToken"] = result.AccessToken;
        }

        WriteJson(report);
    }

    private static Dictionary<string, object?> ReadSanitizedJwtClaims(string accessToken)
    {
        var output = new Dictionary<string, object?>();
        string[] segments = accessToken.Split('.');
        if (segments.Length < 2)
        {
            output["format"] = "opaque";
            return output;
        }

        try
        {
            byte[] payload = Base64UrlDecode(segments[1]);
            using JsonDocument document = JsonDocument.Parse(payload);
            string[] allowList =
            {
                "aud", "tid", "scp", "roles", "xms_cc", "iat", "nbf", "exp",
                "iss", "appid", "azp", "idtyp", "cnf"
            };

            foreach (string name in allowList)
            {
                if (document.RootElement.TryGetProperty(name, out JsonElement value))
                {
                    output[name] = JsonSerializer.Deserialize<object>(value.GetRawText());
                }
            }
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            output["format"] = "jwt_unparseable";
        }

        return output;
    }

    private static byte[] Base64UrlDecode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + ((4 - padded.Length % 4) % 4), '=');
        return Convert.FromBase64String(padded);
    }

    private static void WriteMsalError(string status, MsalException ex)
    {
        var report = new Dictionary<string, object?>
        {
            ["status"] = status,
            ["errorCode"] = ex.ErrorCode,
            ["correlationId"] = ex.CorrelationId
        };

        if (ex is MsalUiRequiredException uiRequired)
        {
            report["classification"] = uiRequired.Classification.ToString();
            report["claimsChallengePresent"] = !string.IsNullOrWhiteSpace(uiRequired.Claims);
        }

        WriteJson(report);
    }

    private static void WriteJson(object value) =>
        Console.WriteLine(JsonSerializer.Serialize(value, new JsonSerializerOptions
        {
            WriteIndented = true
        }));

    private static void PrintHelp(TextWriter writer)
    {
        writer.WriteLine("WAM/MSAL silent-acquisition reference client");
        writer.WriteLine();
        writer.WriteLine("Usage:");
        writer.WriteLine("  askwam-reference-msal [options]");
        writer.WriteLine();
        writer.WriteLine("Options:");
        writer.WriteLine($"  --client-id <guid>     Public client ID (default: Teams {TeamsDesktopClientId})");
        writer.WriteLine($"  --scope <scope>        Repeatable scope (default: {GraphDefaultScope})");
        writer.WriteLine("  --tenant <tenant>      Tenant ID/name or HTTPS authority (default: organizations)");
        writer.WriteLine("  --cae                  Advertise the cp1 CAE client capability");
        writer.WriteLine("  --claims-json <json>   Raw OAuth claims object or claims challenge");
        writer.WriteLine("  --claims-file <path>   Read raw OAuth claims JSON from a UTF-8 file");
        writer.WriteLine("  --hide                 Omit the access token from stdout");
        writer.WriteLine("  -h, --help             Show this help");
        writer.WriteLine();
        writer.WriteLine("The client never falls back to interactive authentication.");
    }

    private sealed record Options(
        string ClientId,
        IReadOnlyList<string> Scopes,
        string Tenant,
        bool EnableCae,
        string? ClaimsJson,
        string? ClaimsFile,
        bool HideToken,
        bool Help)
    {
        public static Options Parse(string[] args)
        {
            string clientId = TeamsDesktopClientId;
            var scopes = new List<string>();
            string tenant = "organizations";
            bool enableCae = false;
            string? claimsJson = null;
            string? claimsFile = null;
            bool hideToken = false;
            bool help = false;

            for (int index = 0; index < args.Length; index++)
            {
                string argument = args[index];
                switch (argument)
                {
                    case "--client-id":
                        clientId = NextValue(args, ref index, argument);
                        break;
                    case "--scope":
                        scopes.Add(NextValue(args, ref index, argument));
                        break;
                    case "--tenant":
                        tenant = NextValue(args, ref index, argument);
                        break;
                    case "--claims-json":
                        claimsJson = NextValue(args, ref index, argument);
                        break;
                    case "--claims-file":
                        claimsFile = NextValue(args, ref index, argument);
                        break;
                    case "--cae":
                        enableCae = true;
                        break;
                    case "--hide":
                        hideToken = true;
                        break;
                    case "-h":
                    case "--help":
                        help = true;
                        break;
                    default:
                        throw new ArgumentException($"Unknown argument: {argument}");
                }
            }

            if (claimsJson is not null && claimsFile is not null)
            {
                throw new ArgumentException("Use either --claims-json or --claims-file, not both.");
            }

            if (!Guid.TryParse(clientId, out _))
            {
                throw new ArgumentException("--client-id must be a GUID.");
            }

            if (scopes.Count == 0)
            {
                scopes.Add(GraphDefaultScope);
            }

            return new Options(
                clientId,
                scopes,
                tenant,
                enableCae,
                claimsJson,
                claimsFile,
                hideToken,
                help);
        }

        private static string NextValue(string[] args, ref int index, string option)
        {
            if (++index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
            {
                throw new ArgumentException($"Missing value for {option}.");
            }

            return args[index];
        }
    }
}
