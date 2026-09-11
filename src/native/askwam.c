#define COBJMACROS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#include <inspectable.h>
#include <windows.security.authentication.web.core.h>

#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "runtimeobject.lib")

typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIWebAuthenticationCoreManagerStatics WamStatics;
typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIWebAuthenticationCoreManagerStatics4 WamStatics4;
typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIWebTokenRequestFactory TokenRequestFactory;
typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIWebTokenRequest TokenRequest;
typedef __x_ABI_CWindows_CSecurity_CCredentials_CIWebAccountProvider WebAccountProvider;
typedef __x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount WebAccount;
typedef __x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount2 WebAccount2;
typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIFindAllAccountsResult FindAllAccountsResult;
typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIWebTokenRequestResult TokenRequestResult;
typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIWebTokenResponse TokenResponse;
typedef __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CIWebProviderError ProviderError;
typedef __FIAsyncOperation_1_Windows__CSecurity__CCredentials__CWebAccountProvider ProviderOperation;
typedef __FIAsyncOperation_1_Windows__CSecurity__CCredentials__CWebAccount AccountOperation;
typedef __FIAsyncOperation_1_Windows__CSecurity__CAuthentication__CWeb__CCore__CFindAllAccountsResult FindAccountsOperation;
typedef __FIAsyncOperation_1_Windows__CSecurity__CAuthentication__CWeb__CCore__CWebTokenRequestResult TokenOperation;
typedef __FIVectorView_1_Windows__CSecurity__CAuthentication__CWeb__CCore__CWebTokenResponse TokenResponseView;
typedef __FIVectorView_1_Windows__CSecurity__CCredentials__CWebAccount WebAccountView;
typedef __FIMap_2_HSTRING_HSTRING StringMap;

static const GUID IID_WamStatics =
    {0x6aca7c92, 0xa581, 0x4479, {0x9c, 0x10, 0x75, 0x2e, 0xff, 0x44, 0xfd, 0x34}};
static const GUID IID_TokenRequestFactory =
    {0x6cf2141c, 0x0ff0, 0x4c67, {0xb8, 0x4f, 0x99, 0xdd, 0xbe, 0x4a, 0x72, 0xc9}};
static const GUID IID_WamStatics4 =
    {0x54e633fe, 0x96e0, 0x41e8, {0x98, 0x32, 0x12, 0x98, 0x89, 0x7c, 0x2a, 0xaf}};
static const GUID IID_WebAccount2 =
    {0x7b56d6f8, 0x990b, 0x4eb5, {0x94, 0xa7, 0x56, 0x21, 0xf3, 0xa8, 0xb8, 0x24}};

static const wchar_t DEFAULT_CLIENT_ID[] = L"1fec8e78-bce4-4aaf-ab1b-5451cc387264";
static const wchar_t DEFAULT_SCOPE[] = L"https://graph.microsoft.com/.default";
static const wchar_t DEFAULT_AUTHORITY[] = L"organizations";
static const wchar_t PROVIDER_ID[] = L"https://login.microsoft.com";
static const wchar_t MANAGER_CLASS[] = L"Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager";
static const wchar_t REQUEST_CLASS[] = L"Windows.Security.Authentication.Web.Core.WebTokenRequest";
static const wchar_t CAE_CLAIMS[] = L"{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\"]}}}";
static const wchar_t RESERVED_SCOPES[] = L" openid offline_access profile";

typedef struct Options {
    const wchar_t *client_id;
    const wchar_t *scope;
    const wchar_t *resource;
    const wchar_t *authority;
    const wchar_t *claims;
    DWORD timeout_ms;
    int cae;
    int hide_token;
    int enumerate_accounts;
    const wchar_t *account_id;
    const wchar_t *username;
} Options;

static void release_unknown(void *object)
{
    if (object != NULL) {
        IUnknown_Release((IUnknown *)object);
    }
}

static HRESULT make_hstring(const wchar_t *value, HSTRING *result)
{
    return WindowsCreateString(value, (UINT32)wcslen(value), result);
}

static HRESULT wait_async(IUnknown *operation, DWORD timeout_ms)
{
    IAsyncInfo *info = NULL;
    ULONGLONG started = GetTickCount64();
    HRESULT hr = IUnknown_QueryInterface(operation, &IID_IAsyncInfo, (void **)&info);
    if (FAILED(hr)) {
        return hr;
    }

    for (;;) {
        AsyncStatus status = Started;
        hr = IAsyncInfo_get_Status(info, &status);
        if (FAILED(hr)) {
            break;
        }
        if (status == Completed) {
            hr = S_OK;
            break;
        }
        if (status == Canceled) {
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            break;
        }
        if (status == Error) {
            hr = E_FAIL;
            IAsyncInfo_get_ErrorCode(info, &hr);
            break;
        }
        if (GetTickCount64() - started >= timeout_ms) {
            IAsyncInfo_Cancel(info);
            hr = HRESULT_FROM_WIN32(WAIT_TIMEOUT);
            break;
        }
        Sleep(25);
    }

    IAsyncInfo_Release(info);
    return hr;
}

static HRESULT insert_property(StringMap *properties, const wchar_t *key, const wchar_t *value)
{
    HSTRING hkey = NULL;
    HSTRING hvalue = NULL;
    boolean replaced = FALSE;
    HRESULT hr = make_hstring(key, &hkey);
    if (SUCCEEDED(hr)) {
        hr = make_hstring(value, &hvalue);
    }
    if (SUCCEEDED(hr)) {
        hr = properties->lpVtbl->Insert(properties, hkey, hvalue, &replaced);
    }
    WindowsDeleteString(hvalue);
    WindowsDeleteString(hkey);
    return hr;
}

static void print_json_string(const wchar_t *value)
{
    const wchar_t *cursor;
    wprintf(L"\"");
    for (cursor = value; *cursor != L'\0'; ++cursor) {
        switch (*cursor) {
            case L'\"': wprintf(L"\\\""); break;
            case L'\\': wprintf(L"\\\\"); break;
            case L'\b': wprintf(L"\\b"); break;
            case L'\f': wprintf(L"\\f"); break;
            case L'\n': wprintf(L"\\n"); break;
            case L'\r': wprintf(L"\\r"); break;
            case L'\t': wprintf(L"\\t"); break;
            default:
                if (*cursor < 0x20) wprintf(L"\\u%04X", (unsigned int)*cursor);
                else wprintf(L"%lc", *cursor);
                break;
        }
    }
    wprintf(L"\"");
}

static HRESULT get_account_fields(WebAccount *account, HSTRING *id, HSTRING *username,
                                  enum __x_ABI_CWindows_CSecurity_CCredentials_CWebAccountState *state)
{
    WebAccount2 *account2 = NULL;
    HRESULT hr = account->lpVtbl->get_UserName(account, username);
    if (SUCCEEDED(hr)) hr = account->lpVtbl->get_State(account, state);
    if (SUCCEEDED(hr)) hr = account->lpVtbl->QueryInterface(account, &IID_WebAccount2, (void **)&account2);
    if (SUCCEEDED(hr)) hr = account2->lpVtbl->get_Id(account2, id);
    release_unknown(account2);
    return hr;
}

static const wchar_t *account_state_name(
    enum __x_ABI_CWindows_CSecurity_CCredentials_CWebAccountState state)
{
    switch (state) {
        case WebAccountState_None: return L"None";
        case WebAccountState_Connected: return L"Connected";
        case WebAccountState_Error: return L"Error";
        default: return L"Unknown";
    }
}

static HRESULT print_account(WebAccount *account)
{
    HSTRING id = NULL, username = NULL;
    enum __x_ABI_CWindows_CSecurity_CCredentials_CWebAccountState state;
    const wchar_t *id_text, *username_text;
    HRESULT hr = get_account_fields(account, &id, &username, &state);
    if (FAILED(hr)) goto cleanup;
    id_text = WindowsGetStringRawBuffer(id, NULL);
    username_text = WindowsGetStringRawBuffer(username, NULL);
    wprintf(L"{\"accountId\":");
    print_json_string(id_text);
    wprintf(L",\"username\":");
    print_json_string(username_text);
    wprintf(L",\"state\":\"%ls\"}", account_state_name(state));
cleanup:
    WindowsDeleteString(username);
    WindowsDeleteString(id);
    return hr;
}

static void print_provider_error(TokenRequestResult *result)
{
    ProviderError *error = NULL;
    UINT32 code = 0;
    HSTRING message = NULL;
    UINT32 length = 0;
    const wchar_t *text = NULL;

    if (FAILED(result->lpVtbl->get_ResponseError(result, &error)) || error == NULL) {
        return;
    }
    error->lpVtbl->get_ErrorCode(error, &code);
    if (SUCCEEDED(error->lpVtbl->get_ErrorMessage(error, &message))) {
        text = WindowsGetStringRawBuffer(message, &length);
    }
    fwprintf(stderr, L",\"providerError\":\"0x%08X\"", code);
    if (text != NULL && length != 0) {
        fwprintf(stderr, L",\"providerMessageLength\":%u", length);
    }
    WindowsDeleteString(message);
    release_unknown(error);
}

static int acquire(const Options *options)
{
    HRESULT hr = S_OK;
    int exit_code = 40;
    HSTRING manager_class = NULL, request_class = NULL;
    HSTRING provider_id = NULL, authority = NULL, scope = NULL, client_id = NULL;
    WamStatics *statics = NULL;
    WamStatics4 *statics4 = NULL;
    TokenRequestFactory *factory = NULL;
    ProviderOperation *provider_operation = NULL;
    AccountOperation *account_operation = NULL;
    FindAccountsOperation *accounts_operation = NULL;
    WebAccountProvider *provider = NULL;
    WebAccount *selected_account = NULL;
    FindAllAccountsResult *accounts_result = NULL;
    WebAccountView *accounts = NULL;
    TokenRequest *request = NULL;
    StringMap *properties = NULL;
    TokenOperation *token_operation = NULL;
    TokenRequestResult *result = NULL;
    TokenResponseView *responses = NULL;
    TokenResponse *response = NULL;
    HSTRING token = NULL;
    wchar_t scope_buffer[4096];

#define CHECK(call) do { hr = (call); if (FAILED(hr)) goto cleanup; } while (0)

    scope_buffer[0] = L'\0';
    if (options->resource == NULL) {
        if (wcslen(options->scope) + wcslen(RESERVED_SCOPES) + 1 > ARRAYSIZE(scope_buffer)) {
            fwprintf(stderr, L"{\"status\":\"input_error\",\"message\":\"scope is too long\"}\n");
            exit_code = 2;
            goto cleanup;
        }
        wcscpy_s(scope_buffer, ARRAYSIZE(scope_buffer), options->scope);
        wcscat_s(scope_buffer, ARRAYSIZE(scope_buffer), RESERVED_SCOPES);
    }

    CHECK(make_hstring(MANAGER_CLASS, &manager_class));
    CHECK(RoGetActivationFactory(manager_class, &IID_WamStatics, (void **)&statics));
    CHECK(make_hstring(PROVIDER_ID, &provider_id));
    CHECK(make_hstring(options->authority, &authority));
    CHECK(statics->lpVtbl->FindAccountProviderWithAuthorityAsync(
        statics, provider_id, authority, &provider_operation));
    CHECK(wait_async((IUnknown *)provider_operation, options->timeout_ms));
    CHECK(provider_operation->lpVtbl->GetResults(provider_operation, &provider));
    if (provider == NULL) {
        fwprintf(stderr, L"{\"status\":\"account_provider_not_available\"}\n");
        exit_code = 30;
        goto cleanup;
    }

    CHECK(make_hstring(options->client_id, &client_id));

    if (options->enumerate_accounts || options->username != NULL) {
        enum __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CFindAllWebAccountsStatus account_status;
        UINT32 count = 0, index, matches = 0;
        CHECK(statics->lpVtbl->QueryInterface(statics, &IID_WamStatics4, (void **)&statics4));
        CHECK(statics4->lpVtbl->FindAllAccountsWithClientIdAsync(
            statics4, provider, client_id, &accounts_operation));
        CHECK(wait_async((IUnknown *)accounts_operation, options->timeout_ms));
        CHECK(accounts_operation->lpVtbl->GetResults(accounts_operation, &accounts_result));
        CHECK(accounts_result->lpVtbl->get_Status(accounts_result, &account_status));
        if (account_status != FindAllWebAccountsStatus_Success) {
            fwprintf(stderr, L"{\"status\":\"account_discovery_failed\",\"accountStatus\":%d}\n",
                     (int)account_status);
            exit_code = 31;
            goto cleanup;
        }
        CHECK(accounts_result->lpVtbl->get_Accounts(accounts_result, &accounts));
        CHECK(accounts->lpVtbl->get_Size(accounts, &count));

        if (options->enumerate_accounts) {
            wprintf(L"{\"status\":\"success\",\"operation\":\"account_enumeration\","
                    L"\"clientId\":");
            print_json_string(options->client_id);
            wprintf(L",\"authority\":");
            print_json_string(options->authority);
            wprintf(L",\"accountCount\":%u,\"accounts\":[", count);
            for (index = 0; index < count; ++index) {
                WebAccount *account = NULL;
                CHECK(accounts->lpVtbl->GetAt(accounts, index, &account));
                if (index != 0) wprintf(L",");
                hr = print_account(account);
                release_unknown(account);
                if (FAILED(hr)) goto cleanup;
            }
            wprintf(L"]}\n");
            exit_code = 0;
            goto cleanup;
        }

        for (index = 0; index < count; ++index) {
            WebAccount *account = NULL;
            HSTRING username = NULL;
            const wchar_t *username_text;
            CHECK(accounts->lpVtbl->GetAt(accounts, index, &account));
            hr = account->lpVtbl->get_UserName(account, &username);
            if (FAILED(hr)) {
                release_unknown(account);
                goto cleanup;
            }
            username_text = WindowsGetStringRawBuffer(username, NULL);
            if (CompareStringOrdinal(username_text, -1, options->username, -1, TRUE) == CSTR_EQUAL) {
                ++matches;
                if (selected_account == NULL) selected_account = account;
                else release_unknown(account);
            } else {
                release_unknown(account);
            }
            WindowsDeleteString(username);
        }
        if (matches != 1) {
            fwprintf(stderr, L"{\"status\":\"%ls\",\"matchCount\":%u}\n",
                     matches == 0 ? L"account_not_found" : L"account_ambiguous", matches);
            exit_code = matches == 0 ? 33 : 34;
            goto cleanup;
        }
    } else if (options->account_id != NULL) {
        HSTRING account_id = NULL;
        CHECK(make_hstring(options->account_id, &account_id));
        hr = statics->lpVtbl->FindAccountAsync(statics, provider, account_id, &account_operation);
        WindowsDeleteString(account_id);
        CHECK(hr);
        CHECK(wait_async((IUnknown *)account_operation, options->timeout_ms));
        CHECK(account_operation->lpVtbl->GetResults(account_operation, &selected_account));
        if (selected_account == NULL) {
            fwprintf(stderr, L"{\"status\":\"account_not_found\"}\n");
            exit_code = 33;
            goto cleanup;
        }
    }

    CHECK(make_hstring(REQUEST_CLASS, &request_class));
    CHECK(RoGetActivationFactory(request_class, &IID_TokenRequestFactory, (void **)&factory));
    CHECK(make_hstring(scope_buffer, &scope));
    CHECK(factory->lpVtbl->CreateWithPromptType(
        factory, provider, scope, client_id, WebTokenRequestPromptType_Default, &request));
    CHECK(request->lpVtbl->get_Properties(request, &properties));
    if (options->resource != NULL) {
        CHECK(insert_property(properties, L"resource", options->resource));
    } else {
        CHECK(insert_property(properties, L"wam_compat", L"2.0"));
    }
    if (options->claims != NULL) {
        CHECK(insert_property(properties, L"claims", options->claims));
    } else if (options->cae) {
        CHECK(insert_property(properties, L"claims", CAE_CLAIMS));
    }

    if (selected_account == NULL) {
        CHECK(statics->lpVtbl->GetTokenSilentlyAsync(statics, request, &token_operation));
    } else {
        CHECK(statics->lpVtbl->GetTokenSilentlyWithWebAccountAsync(
            statics, request, selected_account, &token_operation));
    }
    CHECK(wait_async((IUnknown *)token_operation, options->timeout_ms));
    CHECK(token_operation->lpVtbl->GetResults(token_operation, &result));

    {
        enum __x_ABI_CWindows_CSecurity_CAuthentication_CWeb_CCore_CWebTokenRequestStatus status;
        CHECK(result->lpVtbl->get_ResponseStatus(result, &status));
        if (status != WebTokenRequestStatus_Success) {
            fwprintf(stderr, L"{\"status\":\"token_error\",\"responseStatus\":%d", (int)status);
            print_provider_error(result);
            fwprintf(stderr, L"}\n");
            exit_code = (status == WebTokenRequestStatus_UserInteractionRequired) ? 20 : 32;
            goto cleanup;
        }
    }

    CHECK(result->lpVtbl->get_ResponseData(result, &responses));
    {
        UINT32 count = 0;
        CHECK(responses->lpVtbl->get_Size(responses, &count));
        if (count == 0) {
            hr = E_UNEXPECTED;
            goto cleanup;
        }
    }
    CHECK(responses->lpVtbl->GetAt(responses, 0, &response));
    CHECK(response->lpVtbl->get_Token(response, &token));
    {
        WebAccount *response_account = NULL;
        UINT32 token_length = 0;
        const wchar_t *token_text = WindowsGetStringRawBuffer(token, &token_length);
        wprintf(L"{\"status\":\"success\",\"requestMode\":\"%ls\",\"claimsRequested\":%ls,\"tokenLength\":%u",
                options->resource == NULL ? L"scope" : L"resource",
                (options->claims != NULL || options->cae) ? L"true" : L"false",
                token_length);
        if (!options->hide_token) {
            wprintf(L",\"accessToken\":\"%ls\"", token_text);
        }
        if (SUCCEEDED(response->lpVtbl->get_WebAccount(response, &response_account)) && response_account != NULL) {
            wprintf(L",\"account\":");
            hr = print_account(response_account);
            release_unknown(response_account);
            if (FAILED(hr)) goto cleanup;
        }
        wprintf(L"}\n");
    }
    exit_code = 0;

cleanup:
    if (FAILED(hr) && exit_code == 40) {
        fwprintf(stderr, L"{\"status\":\"runtime_error\",\"hresult\":\"0x%08X\"}\n", (UINT32)hr);
    }
    WindowsDeleteString(token);
    release_unknown(response);
    release_unknown(responses);
    release_unknown(result);
    release_unknown(token_operation);
    release_unknown(properties);
    release_unknown(request);
    release_unknown(factory);
    WindowsDeleteString(client_id);
    WindowsDeleteString(scope);
    WindowsDeleteString(request_class);
    release_unknown(provider);
    release_unknown(accounts);
    release_unknown(accounts_result);
    release_unknown(accounts_operation);
    release_unknown(selected_account);
    release_unknown(account_operation);
    release_unknown(provider_operation);
    release_unknown(statics4);
    WindowsDeleteString(authority);
    WindowsDeleteString(provider_id);
    release_unknown(statics);
    WindowsDeleteString(manager_class);
    return exit_code;

#undef CHECK
}

static void print_help(void)
{
    wprintf(L"askWAM - silent Windows WAM token acquisition\n\n"
            L"Usage: askwam [options]\n\n"
            L"  --client-id VALUE       Public client ID (default: Microsoft Teams)\n"
            L"  --scope VALUE           v2 scope string (default: Graph .default)\n"
            L"  --resource VALUE        WAM v1-compatible resource; exclusive with --scope\n"
            L"  --authority VALUE       Provider authority (default: organizations)\n"
            L"  --enum                  Enumerate accounts and exit\n"
            L"  --account-id VALUE      Select an exact WAM account ID\n"
            L"  --username VALUE        Select one exact, unique username\n"
            L"  --claims-json VALUE     Raw OAuth claims object\n"
            L"  --cae                   Request CAE client capability cp1\n"
            L"  --hide                  Omit the access token from output\n"
            L"  --timeout-seconds N     1-300 seconds (default: 30)\n"
            L"  --help                  Show this help\n\n"
            L"Scope mode adds openid, offline_access, and profile for WAM v2 compatibility.\n"
            L"Resource mode sends an empty scope plus the WAM resource property.\n");
}

int wmain(int argc, wchar_t **argv)
{
    Options options = {
        DEFAULT_CLIENT_ID,
        NULL,
        NULL,
        DEFAULT_AUTHORITY,
        NULL,
        30000,
        0,
        0,
        0,
        NULL,
        NULL
    };
    int i;
    HRESULT hr;
    int exit_code;

    for (i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--help") == 0) {
            print_help();
            return 0;
        } else if (wcscmp(argv[i], L"--cae") == 0) {
            options.cae = 1;
        } else if (wcscmp(argv[i], L"--hide") == 0) {
            options.hide_token = 1;
        } else if (wcscmp(argv[i], L"--enum") == 0) {
            options.enumerate_accounts = 1;
        } else if ((wcscmp(argv[i], L"--client-id") == 0 ||
                    wcscmp(argv[i], L"--scope") == 0 ||
                    wcscmp(argv[i], L"--resource") == 0 ||
                    wcscmp(argv[i], L"--authority") == 0 ||
                    wcscmp(argv[i], L"--account-id") == 0 ||
                    wcscmp(argv[i], L"--username") == 0 ||
                    wcscmp(argv[i], L"--claims-json") == 0 ||
                    wcscmp(argv[i], L"--timeout-seconds") == 0) && i + 1 < argc) {
            const wchar_t *name = argv[i++];
            if (wcscmp(name, L"--client-id") == 0) options.client_id = argv[i];
            else if (wcscmp(name, L"--scope") == 0) options.scope = argv[i];
            else if (wcscmp(name, L"--resource") == 0) options.resource = argv[i];
            else if (wcscmp(name, L"--authority") == 0) options.authority = argv[i];
            else if (wcscmp(name, L"--account-id") == 0) options.account_id = argv[i];
            else if (wcscmp(name, L"--username") == 0) options.username = argv[i];
            else if (wcscmp(name, L"--claims-json") == 0) options.claims = argv[i];
            else {
                wchar_t *end = NULL;
                unsigned long seconds = wcstoul(argv[i], &end, 10);
                if (end == argv[i] || *end != L'\0' || seconds < 1 || seconds > 300) {
                    fwprintf(stderr, L"Invalid --timeout-seconds value.\n");
                    return 2;
                }
                options.timeout_ms = (DWORD)(seconds * 1000);
            }
        } else {
            fwprintf(stderr, L"Unknown or incomplete option: %ls\n", argv[i]);
            return 2;
        }
    }

    if (options.cae && options.claims != NULL) {
        fwprintf(stderr, L"Use either --cae or --claims-json, not both.\n");
        return 2;
    }
    if (options.scope != NULL && options.resource != NULL) {
        fwprintf(stderr, L"Use either --scope or --resource, not both.\n");
        return 2;
    }
    if (options.scope == NULL && options.resource == NULL) {
        options.scope = DEFAULT_SCOPE;
    }
    if (options.account_id != NULL && options.username != NULL) {
        fwprintf(stderr, L"Use either --account-id or --username, not both.\n");
        return 2;
    }
    if (options.enumerate_accounts && (options.account_id != NULL || options.username != NULL)) {
        fwprintf(stderr, L"--enum cannot be combined with an account selector.\n");
        return 2;
    }
    if (options.claims != NULL) {
        const wchar_t *start = options.claims;
        const wchar_t *end = options.claims + wcslen(options.claims);
        while (*start == L' ' || *start == L'\t' || *start == L'\r' || *start == L'\n') ++start;
        while (end > start && (end[-1] == L' ' || end[-1] == L'\t' || end[-1] == L'\r' || end[-1] == L'\n')) --end;
        if (end <= start || *start != L'{' || end[-1] != L'}') {
            fwprintf(stderr, L"--claims-json must have a JSON object root.\n");
            return 2;
        }
    }

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        fwprintf(stderr, L"{\"status\":\"runtime_error\",\"hresult\":\"0x%08X\"}\n", (UINT32)hr);
        return 40;
    }
    exit_code = acquire(&options);
    if (hr != RPC_E_CHANGED_MODE) {
        RoUninitialize();
    }
    return exit_code;
}
