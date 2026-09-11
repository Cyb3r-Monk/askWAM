using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web.Core;
using Windows.Security.Credentials;

namespace AskWam
{
    internal static class Program
    {
        private const string TeamsDesktopClientId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264";
        private const string GraphDefaultScope = "https://graph.microsoft.com/.default";
        private const string MicrosoftProviderId = "https://login.microsoft.com";
        private const string CaeClaims = "{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\"]}}}";
        private static readonly string[] ReservedScopes = { "openid", "offline_access", "profile" };

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
                string claims = options.EnumerateAccounts ? null : LoadClaims(options);
                if (claims != null)
                {
                    ValidateClaimsObject(claims);
                }

                using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds)))
                {
                    WebAccountProvider provider = await WebAuthenticationCoreManager
                        .FindAccountProviderAsync(MicrosoftProviderId, options.Authority)
                        .AsTask(timeout.Token)
                        .ConfigureAwait(false);

                    if (provider == null)
                    {
                        WriteLine(Console.Error, "status", "account_provider_not_available");
                        WriteLine(Console.Error, "providerId", MicrosoftProviderId);
                        WriteLine(Console.Error, "authority", options.Authority);
                        return 30;
                    }

                    if (options.EnumerateAccounts)
                    {
                        FindAllAccountsResult accountResult = await FindAccountsAsync(provider, options, timeout.Token);
                        if (accountResult.Status != FindAllWebAccountsStatus.Success)
                        {
                            WriteAccountDiscoveryError(options, accountResult);
                            return 31;
                        }

                        WriteAccounts(options, provider, accountResult.Accounts);
                        return 0;
                    }

                    WebAccount selectedAccount = null;
                    if (options.AccountId != null)
                    {
                        selectedAccount = await WebAuthenticationCoreManager
                            .FindAccountAsync(provider, options.AccountId)
                            .AsTask(timeout.Token)
                            .ConfigureAwait(false);

                        if (selectedAccount == null)
                        {
                            WriteAccountSelectionError(options, "account_not_found", null);
                            return 33;
                        }
                    }
                    else if (options.Username != null)
                    {
                        FindAllAccountsResult accountResult = await FindAccountsAsync(provider, options, timeout.Token);
                        if (accountResult.Status != FindAllWebAccountsStatus.Success)
                        {
                            WriteAccountDiscoveryError(options, accountResult);
                            return 31;
                        }

                        WebAccount[] matches = accountResult.Accounts
                            .Where(account => string.Equals(account.UserName, options.Username, StringComparison.OrdinalIgnoreCase))
                            .ToArray();

                        if (matches.Length != 1)
                        {
                            WriteAccountSelectionError(
                                options,
                                matches.Length == 0 ? "account_not_found" : "account_ambiguous",
                                matches);
                            return matches.Length == 0 ? 33 : 34;
                        }

                        selectedAccount = matches[0];
                    }

                    WebTokenRequest request = CreateRequest(provider, options, claims);
                    WebTokenRequestResult result = selectedAccount == null
                        ? await WebAuthenticationCoreManager.GetTokenSilentlyAsync(request).AsTask(timeout.Token).ConfigureAwait(false)
                        : await WebAuthenticationCoreManager.GetTokenSilentlyAsync(request, selectedAccount).AsTask(timeout.Token).ConfigureAwait(false);

                    if (result.ResponseStatus == WebTokenRequestStatus.Success)
                    {
                        WriteSuccess(options, claims, result.ResponseData[0]);
                        return 0;
                    }

                    WriteTokenError(options, result);
                    return result.ResponseStatus == WebTokenRequestStatus.UserInteractionRequired ? 20 : 32;
                }
            }
            catch (OperationCanceledException)
            {
                WriteLine(Console.Error, "status", "timeout");
                WriteLine(Console.Error, "timeoutSeconds", options.TimeoutSeconds);
                return 23;
            }
            catch (Exception ex) when (ex is ArgumentException || ex is IOException)
            {
                WriteLine(Console.Error, "status", "input_error");
                WriteLine(Console.Error, "errorType", ex.GetType().Name);
                WriteLine(Console.Error, "message", ex.Message);
                return 2;
            }
            catch (Exception ex)
            {
                WriteLine(Console.Error, "status", "runtime_error");
                WriteLine(Console.Error, "errorType", ex.GetType().Name);
                WriteLine(Console.Error, "hresult", string.Format("0x{0:X8}", ex.HResult));
                return 40;
            }
        }

        private static WebTokenRequest CreateRequest(WebAccountProvider provider, Options options, string claims)
        {
            bool resourceMode = options.Resource != null;
            string scope = resourceMode ? string.Empty : string.Join(" ", GetScopesSent(options.Scopes));
            var request = new WebTokenRequest(provider, scope, options.ClientId, WebTokenRequestPromptType.Default);

            if (resourceMode)
            {
                request.Properties["resource"] = options.Resource;
            }
            else
            {
                request.Properties["wam_compat"] = "2.0";
            }

            if (claims != null)
            {
                request.Properties["claims"] = claims;
            }

            return request;
        }

        private static async Task<FindAllAccountsResult> FindAccountsAsync(WebAccountProvider provider, Options options, CancellationToken cancellationToken)
        {
            return await WebAuthenticationCoreManager
                .FindAllAccountsAsync(provider, options.ClientId)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
        }

        private static IReadOnlyList<string> GetScopesSent(IEnumerable<string> requestedScopes)
        {
            var scopes = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string scope in requestedScopes.Concat(ReservedScopes))
            {
                if (seen.Add(scope))
                {
                    scopes.Add(scope);
                }
            }
            return scopes;
        }

        private static string LoadClaims(Options options)
        {
            if (options.EnableCae)
            {
                return CaeClaims;
            }
            if (options.ClaimsFile != null)
            {
                return File.ReadAllText(options.ClaimsFile, Encoding.UTF8);
            }
            return options.ClaimsJson;
        }

        private static void ValidateClaimsObject(string claims)
        {
            string trimmed = claims.Trim();
            if (trimmed.Length < 2 || trimmed[0] != '{' || trimmed[trimmed.Length - 1] != '}')
            {
                throw new ArgumentException("Claims JSON must have a JSON object at its root.");
            }
        }

        private static void WriteRequest(TextWriter writer, Options options)
        {
            WriteLine(writer, "clientId", options.ClientId);
            WriteLine(writer, "providerId", MicrosoftProviderId);
            WriteLine(writer, "authority", options.Authority);
            if (options.Resource != null)
            {
                WriteLine(writer, "requestMode", "resource");
                WriteLine(writer, "resource", options.Resource);
            }
            else
            {
                WriteLine(writer, "requestMode", "scope");
                WriteLine(writer, "scopesRequested", string.Join(" ", options.Scopes));
                WriteLine(writer, "scopesSent", string.Join(" ", GetScopesSent(options.Scopes)));
            }
        }

        private static void WriteSuccess(Options options, string claims, WebTokenResponse response)
        {
            WriteLine(Console.Out, "status", "success");
            WriteRequest(Console.Out, options);
            WriteLine(Console.Out, "claimsRequested", claims != null ? "true" : "false");
            WriteLine(Console.Out, "tokenLength", response.Token.Length);
            if (!options.HideToken)
            {
                WriteLine(Console.Out, "accessToken", response.Token);
            }
            WriteAccount(Console.Out, response.WebAccount, null);
        }

        private static void WriteAccounts(Options options, WebAccountProvider provider, IReadOnlyList<WebAccount> accounts)
        {
            WriteLine(Console.Out, "status", "success");
            WriteLine(Console.Out, "operation", "account_enumeration");
            WriteLine(Console.Out, "clientId", options.ClientId);
            WriteLine(Console.Out, "providerId", provider.Id);
            WriteLine(Console.Out, "authority", provider.Authority);
            WriteLine(Console.Out, "accountCount", accounts.Count);
            for (int index = 0; index < accounts.Count; index++)
            {
                WriteAccount(Console.Out, accounts[index], index);
            }
        }

        private static void WriteAccount(TextWriter writer, WebAccount account, int? index)
        {
            if (account == null)
            {
                return;
            }
            string prefix = index.HasValue ? string.Format("account[{0}]", index.Value) : "account";
            WriteLine(writer, prefix + ".accountId", account.Id);
            WriteLine(writer, prefix + ".username", account.UserName);
            WriteLine(writer, prefix + ".state", account.State);
        }

        private static void WriteAccountSelectionError(Options options, string status, IReadOnlyList<WebAccount> matches)
        {
            WriteLine(Console.Error, "status", status);
            WriteLine(Console.Error, "clientId", options.ClientId);
            WriteLine(Console.Error, "authority", options.Authority);
            if (options.AccountId != null) WriteLine(Console.Error, "accountId", options.AccountId);
            if (options.Username != null) WriteLine(Console.Error, "username", options.Username);
            if (matches != null) WriteLine(Console.Error, "matchCount", matches.Count);
        }

        private static void WriteAccountDiscoveryError(Options options, FindAllAccountsResult result)
        {
            WriteLine(Console.Error, "status", "account_discovery_failed");
            WriteLine(Console.Error, "accountStatus", result.Status);
            WriteLine(Console.Error, "clientId", options.ClientId);
            WriteLine(Console.Error, "authority", options.Authority);
            if (result.ProviderError != null)
            {
                WriteLine(Console.Error, "providerErrorCode", string.Format("0x{0:X8}", result.ProviderError.ErrorCode));
            }
        }

        private static void WriteTokenError(Options options, WebTokenRequestResult result)
        {
            WriteLine(Console.Error, "status", result == null ? "no_result" : result.ResponseStatus.ToString());
            WriteRequest(Console.Error, options);
            if (result != null && result.ResponseError != null)
            {
                WriteLine(Console.Error, "providerErrorCode", string.Format("0x{0:X8}", result.ResponseError.ErrorCode));
            }
        }

        private static void WriteLine(TextWriter writer, string name, object value)
        {
            writer.WriteLine("{0}={1}", name, value);
        }

        private static void PrintHelp(TextWriter writer)
        {
            writer.WriteLine("askWAM - dependency-minimal WAM silent token client");
            writer.WriteLine();
            writer.WriteLine("Usage:");
            writer.WriteLine("  askwam [options]");
            writer.WriteLine();
            writer.WriteLine("Options:");
            writer.WriteLine("  --client-id <guid>       Public client ID (default: Teams {0})", TeamsDesktopClientId);
            writer.WriteLine("  --scope <scope>          Repeatable v2 scope (default: {0})", GraphDefaultScope);
            writer.WriteLine("  --resource <resource>    WAM v1-compatible resource; exclusive with --scope");
            writer.WriteLine("  --authority <authority>  Provider authority (default: organizations)");
            writer.WriteLine("  --enum                   Enumerate accounts and exit without requesting a token");
            writer.WriteLine("  --account-id <id>        Request a token for an exact WAM account ID");
            writer.WriteLine("  --username <name>        Request a token for one exact, unique username");
            writer.WriteLine("  --cae                    Send the predefined cp1 CAE claims object");
            writer.WriteLine("  --claims-json <json>     Raw OAuth claims object or claims challenge");
            writer.WriteLine("  --claims-file <path>     Read raw OAuth claims JSON from a UTF-8 file");
            writer.WriteLine("  --timeout-seconds <n>    Silent-operation timeout (default: 30)");
            writer.WriteLine("  --hide                   Omit the access token from stdout");
            writer.WriteLine("  -h, --help               Show this help");
            writer.WriteLine();
            writer.WriteLine("--cae, --claims-json, and --claims-file are mutually exclusive.");
            writer.WriteLine("The client never performs interactive authentication.");
        }

        private sealed class Options
        {
            public string ClientId { get; private set; }
            public IReadOnlyList<string> Scopes { get; private set; }
            public string Resource { get; private set; }
            public string Authority { get; private set; }
            public bool EnableCae { get; private set; }
            public string ClaimsJson { get; private set; }
            public string ClaimsFile { get; private set; }
            public int TimeoutSeconds { get; private set; }
            public bool HideToken { get; private set; }
            public bool EnumerateAccounts { get; private set; }
            public string AccountId { get; private set; }
            public string Username { get; private set; }
            public bool Help { get; private set; }

            private Options()
            {
                ClientId = TeamsDesktopClientId;
                Scopes = new List<string>();
                Authority = "organizations";
                TimeoutSeconds = 30;
            }

            public static Options Parse(string[] args)
            {
                var options = new Options();
                var scopes = new List<string>();
                for (int index = 0; index < args.Length; index++)
                {
                    string argument = args[index];
                    switch (argument)
                    {
                        case "--client-id": options.ClientId = NextValue(args, ref index, argument); break;
                        case "--scope": scopes.Add(NextValue(args, ref index, argument)); break;
                        case "--resource": options.Resource = NextValue(args, ref index, argument); break;
                        case "--authority": options.Authority = NextValue(args, ref index, argument); break;
                        case "--account-id": options.AccountId = NextValue(args, ref index, argument); break;
                        case "--username": options.Username = NextValue(args, ref index, argument); break;
                        case "--claims-json": options.ClaimsJson = NextValue(args, ref index, argument); break;
                        case "--claims-file": options.ClaimsFile = NextValue(args, ref index, argument); break;
                        case "--timeout-seconds":
                            int timeoutSeconds;
                            if (!int.TryParse(NextValue(args, ref index, argument), out timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 300)
                            {
                                throw new ArgumentException("--timeout-seconds must be between 1 and 300.");
                            }
                            options.TimeoutSeconds = timeoutSeconds;
                            break;
                        case "--cae": options.EnableCae = true; break;
                        case "--hide": options.HideToken = true; break;
                        case "--enum": options.EnumerateAccounts = true; break;
                        case "-h":
                        case "--help": options.Help = true; break;
                        default: throw new ArgumentException("Unknown argument: " + argument);
                    }
                }

                if (options.ClaimsJson != null && options.ClaimsFile != null)
                    throw new ArgumentException("Use either --claims-json or --claims-file, not both.");
                if (options.EnableCae && (options.ClaimsJson != null || options.ClaimsFile != null))
                    throw new ArgumentException("Use --cae, --claims-json, or --claims-file; these options are mutually exclusive.");
                if (options.Resource != null && scopes.Count != 0)
                    throw new ArgumentException("Use either --resource or --scope, not both.");
                if (options.AccountId != null && options.Username != null)
                    throw new ArgumentException("Use either --account-id or --username, not both.");
                if (options.EnumerateAccounts && (options.AccountId != null || options.Username != null))
                    throw new ArgumentException("--enum cannot be combined with an account selector.");
                Guid clientId;
                if (!Guid.TryParse(options.ClientId, out clientId))
                    throw new ArgumentException("--client-id must be a GUID.");
                if (scopes.Count == 0 && options.Resource == null)
                    scopes.Add(GraphDefaultScope);

                options.Scopes = scopes;
                return options;
            }

            private static string NextValue(string[] args, ref int index, string option)
            {
                if (++index >= args.Length || string.IsNullOrWhiteSpace(args[index]))
                    throw new ArgumentException("Missing value for " + option + ".");
                return args[index];
            }
        }
    }
}
