// Rust Console PSN Bypass Plugin
// Hooks IL2CPP functions to bypass PSN requirements for Rust Console Edition (CUSA14296)
// Allows reaching the main menu without PSN sign-in

#include "plugin_common.h"
#include "Common.h"
#include "mini_hook.h"
#include <stdint.h>
#include <string.h>
#include <orbis/libkernel.h>

// Simple notification helper (can't use NotifyStatic from C code due to C++ name mangling)
static void send_notification(const char* text) {
    OrbisNotificationRequest req;
    memset(&req, 0, sizeof(req));
    req.type = NotificationRequest;
    req.unk3 = 0;
    req.useIconImageUri = 1;
    req.targetId = -1;
    strncpy(req.message, text, sizeof(req.message) - 1);
    strncpy(req.iconUri, TEX_ICON_SYSTEM, sizeof(req.iconUri) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

attr_public const char *g_pluginName = "rust_psn_bypass";
attr_public const char *g_pluginDesc = "Bypass PSN checks for Rust Console Edition";
attr_public const char *g_pluginAuth = "Research";
attr_public u32 g_pluginVersion = 0x00000100;

// =============================================================================
// Offsets from eboot base address (base = 0x400000)
// =============================================================================
#define OFFSET_sceNpGetAccountIdA         0x0155d060
#define OFFSET_sceNpWebApiCreateContextA  0x0155e080
#define OFFSET_sceNpWebApiReadData        0x0155e120
#define OFFSET_sceNpWebApiDeleteRequest   0x0155e160
#define OFFSET_sceNpWebApiInitialize      0x0155e1c0
#define OFFSET_sceNpWebApiCreateRequest   0x0155e210
#define OFFSET_sceNpWebApiSendRequest2    0x0155e240
#define OFFSET_sceKernelLoadStartModule   0x0155d250

// =============================================================================
// IL2CPP function RVAs (in Il2CppUserAssemblies.prx)
// =============================================================================
#define IL2CPP_RUSTWORKS_GET_ROOT       0x2AAEFB0  // Rustworks.get_Root()
#define IL2CPP_DISPLAY_SIGNIN_DIALOG    0x2BF2790  // NpUtils.DisplaySigninDialog()
#define IL2CPP_CHECK_ONLINE_PS4         0x281B170  // ButtonMainMenu.CheckOnline_PS4()
#define IL2CPP_REQUEST_DISPLAY_SIGNON   0x2C60AA0  // PlatformServicesPS4.RequestDisplaySignOnDialog()
#define IL2CPP_PS4_IS_SIGNED_IN         0x2C5FCC0  // PlatformServicesPS4.IsSignedIn()
#define IL2CPP_PS4_CAN_USE_ONLINE       0x2C5CC50  // PlatformServicesPS4.CanUseOnline()
#define IL2CPP_PS4_USER_HAS_MP_PERM     0x2C5C630  // PlatformServicesPS4.UserHasMultiplayerPermission()
#define IL2CPP_PS4_GET_ENGAGED_USER_ID  0x2C5D700  // PlatformServicesPS4.GetEngagedUserID()
#define IL2CPP_FRONTEND_IS_ENGAGED_SIGNED_IN 0x288B930  // FrontendUI.IsEngagedUserSignedIn()
#define IL2CPP_GETENGAGEDUSER_MOVENEXT  0x288C2E0  // FrontendUI.<GetEngagedUser>d__25.MoveNext()
#define IL2CPP_WEBREQUEST_INTERNAL_SET_URL 0x2328DA0 // UnityWebRequest.InternalSetUrl()
#define IL2CPP_COROUTINE_CHECK_ONLINE_MOVENEXT 0x29214A0  // FindJoinGameUI.<Coroutine_CheckOnline>d__97.MoveNext()
#define IL2CPP_PLATFORMSERVICES_GET_RUSTWORKS 0x286DBD0  // PlatformServices.get_Rustworks()
#define IL2CPP_STRING_CREATE_FROM_CHAR 0xED9760  // String.CreateString(char* value)
#define IL2CPP_RUSTWORKS_INITIALISE 0x2AAF090  // Rustworks.Initialise(string root, string metricsRoot, int networkProtocol)

// Unity Debug logging functions
#define IL2CPP_DEBUG_LOG        0x123BD30  // Debug.Log(object message)
#define IL2CPP_DEBUG_LOG_ERROR  0x123BDC0  // Debug.LogError(object message)
#define IL2CPP_DEBUG_LOG_WARNING 0x123C0D0 // Debug.LogWarning(object message)
#define IL2CPP_DEBUG_LOG_EXCEPTION 0x1233420 // Debug.LogException(Exception exception)
#define IL2CPP_DEBUG_IS_DEBUG_BUILD 0x123C2A0 // Debug.get_isDebugBuild()

// Local server mode hooks
#define IL2CPP_LOCALSERVER_GET_IS_RUNNING 0x445620 // LocalServer.get_isRunningLocalServer()

// DTLS encryption hooks - force unencrypted mode for PC server compatibility
// DTLS.Startup is the actual function that initiates DTLS (called by Facepunch.Network.DTLS.Client.Connect)
// RVA 0x1C83A40 from dump.cs - this is an INSTANCE method (has this pointer)
#define IL2CPP_DTLS_STARTUP 0x1C83A40 // DTLS.Startup(bool isServer, string serverAddress, int serverPort, string cipherList, string cipherSuites, bool isUnencrypted)
// Also hook get_IsUnencrypted to always return true
#define IL2CPP_DTLS_GET_ISUNENCRYPTED 0x1C8B7C0 // DTLS.get_IsUnencrypted()

// PSN Room matchmaking bypass - game uses PSN rooms before network connect
// All PSN room functions need to be bypassed since PSN isn't available
// Ghidra addresses, subtract 0x1000000 for RVA
#define IL2CPP_CREATEROOM_WRAPPER  0x2BCB8A0  // PrxCreateRoom (Ghidra 0x3bcb8a0)
#define IL2CPP_LEAVEROOM_WRAPPER   0x2BCB9E0  // PrxLeaveRoom (Ghidra 0x3bcb9e0)
#define IL2CPP_SEARCHROOMS_WRAPPER 0x2BCBB10  // PrxSearchRooms (Ghidra 0x3bcbb10)
#define IL2CPP_JOINROOM_WRAPPER    0x2BCBC20  // PrxJoinRoom (Ghidra 0x3bcbc20)

// PS+ subscription check bypass - this blocks connect flow without PS+
// Ghidra 0x3bf2ab0, RVA = 0x3bf2ab0 - 0x1000000 = 0x2BF2AB0
#define IL2CPP_CHECKPLUS           0x2BF2AB0  // Sony.NP.NpUtils.CheckPlus()
#define IL2CPP_CHECKAVAILABLITY    0x2BF1A80  // Sony.NP.NpUtils.CheckAvailablity() (Ghidra 0x3bf1a80)

// Rustworks API connect function - called when clicking Connect on a server
// Ghidra 0x3aa72b0, RVA = 0x2AA72B0
#define IL2CPP_RUSTWORKS_CONNECT   0x2AA72B0  // D11.Rustworks.Connect()

// UI Connect flow tracing
#define IL2CPP_FINDJOIN_CONNECT    0x291B4C0  // FindJoinGameUI.Connect(int idx)
#define IL2CPP_DOSERVER_PRECONNECT_MOVENEXT 0x29219E0  // Coroutine_DoServerPreconnection.MoveNext
#define IL2CPP_PROCESSSERVERPRECONNECT_MOVENEXT 0x2923940  // ProcessServerPreconnect.MoveNext
#define IL2CPP_CONNECTTOSERVER     0x291CBF0  // FindJoinGameUI.ConnectToServer(ip, port, serverID, nextWipe, owner)

// DTLS InvalidPacket hooks - for debugging packet rejection at DTLS layer
#define IL2CPP_DTLS_CLIENT_INVALIDPACKET 0x1C92E50  // Facepunch.Network.DTLS.Client.InvalidPacket(byte type) - Ghidra 0x02C92E50
#define IL2CPP_DTLS_SERVER_INVALIDPACKET 0x1C9D260  // Facepunch.Network.DTLS.Server.InvalidPacket(byte type, Connection connection) - Ghidra 0x02C9D260

// LiteNetLib InvalidPacket hooks - for debugging packet rejection at LiteNetLib layer
#define IL2CPP_LITENETLIB_CLIENT_INVALIDPACKET 0x135BB60  // Facepunch.Network.LiteNetLib.Client.InvalidPacket(byte type) - Ghidra 0x0235BB60
#define IL2CPP_LITENETLIB_SERVER_INVALIDPACKET 0x1362680  // Facepunch.Network.LiteNetLib.Server.InvalidPacket(byte type, Connection connection) - Ghidra 0x02362680

// D11.Logger hook - for capturing all DTLS logging
#define IL2CPP_LOGGER_WRITELOG 0x23D3010  // D11.Logger.WriteLog(Category, Level, string, string, object[])

// DTLS handshake hook - for monitoring SSL handshake state
#define DTLS_SSL_INFO_CALLBACK 0x1003D90  // FUN_01007d90 - SSL info callback (logs handshake start/done)

// Network message handler hooks - for debugging game protocol
#define IL2CPP_MESSAGE_PROCESS 0x282F660  // Network.MessageProcess(Message packet) - RVA 0x2833660
#define IL2CPP_ON_REQUEST_USER_INFO 0x28352B0  // Network.OnRequestUserInformation(Message packet) - RVA 0x28392B0
#define IL2CPP_REQUEST_USER_INFO_PROCESS 0x282EE40  // Network.RequestUserInformationProcess(Message packet) - RVA 0x2832E40
#define IL2CPP_ON_APPROVED 0x282F6D0  // Network.OnApproved(Message packet) - RVA 0x28336D0
#define IL2CPP_CLIENT_CYCLE 0x1C8FF60  // Client.Cycle() - RVA 0x1C93F60
#define IL2CPP_CLIENT_HANDLE_MESSAGE 0x1C8FB20  // Client.HandleMessage() - RVA 0x1C93B20
#define IL2CPP_NETWORKMESSAGES_RECEIVE 0x237FDE0  // NetworkMessages.ReceiveMessage(Socket, ref Message) - RVA 0x2383DE0
#define IL2CPP_ALIENCLIENT_START 0x237DA60  // AlienClient.Start() - RVA 0x2381A60
#define IL2CPP_ALIENCLIENT_READTHREAD 0x237FB80  // AlienClient.ReadThread() - RVA 0x2383B80
#define IL2CPP_DTLS_PROCESS_RECV_BUFFER 0x1C87C80  // DTLSConnection.ProcessRecvBuffer() - RVA 0x1C87C80

// UnityWebRequest functions for debugging
#define IL2CPP_WEBREQUEST_GET_ERROR 0x232A1F0  // UnityWebRequest.get_error()
#define IL2CPP_WEBREQUEST_GET_URL   0x232A300  // UnityWebRequest.get_url()
#define IL2CPP_WEBREQUEST_IS_NETWORK_ERROR 0x232A4E0 // Approximate - need to verify
#define IL2CPP_RUSTWORKS_REQUEST_COMPLETE 0x238AA40 // Rustworks.Request.Complete(string error)

// Facepunch.Output - central logging for all Rust messages
#define IL2CPP_OUTPUT_LOGHANDLER    0x290B8D0  // Facepunch.Output.LogHandler(string log, string stacktrace, LogType type)
#define IL2CPP_OUTPUT_INSTALL       0x290B770  // Facepunch.Output.Install() - enables logging
// ConsoleUI logging
#define IL2CPP_CONSOLEUI_LOG        0x5BF370   // ConsoleUI.Log(string message)

// Use real user ID from system
#define FAKE_USER_ID 0x142a87ac

// Forward declarations
static void capture_string_klass(void* il2cpp_str);
static int find_dtls_prx_module(void);
static void enable_dtls_native_logging(void);

static uint64_t g_base_address = 0;
static uint64_t g_il2cpp_base_address = 0;
static uint64_t g_dtls_prx_base_address = 0;
static int g_il2cpp_module_handle = -1;
static int g_dtls_prx_module_handle = -1;
static int g_il2cpp_hooks_installed = 0;
static int g_dtls_logging_enabled = 0;

// DTLS.prx native function offsets (from Ghidra analysis)
// FUN_01007840(bool) - enables/disables logging
// FUN_01007880(int) - sets log level (0=all, 1=info, 2=errors)
#define DTLS_PRX_SET_LOGGING_ENABLED_OFFSET 0x7840
#define DTLS_PRX_SET_LOG_LEVEL_OFFSET 0x7880

// Fake context IDs for sceNpWebApi
static int g_fake_lib_ctx = 1;
static int g_fake_web_ctx = 100;
static int g_fake_request_id = 1000;

// =============================================================================
// Hook structures
// =============================================================================
static mh_hook_t g_hook_sceNpGetAccountIdA = {0};
static mh_hook_t g_hook_sceNpWebApiCreateContextA = {0};
static mh_hook_t g_hook_sceNpWebApiReadData = {0};
static mh_hook_t g_hook_sceNpWebApiDeleteRequest = {0};
static mh_hook_t g_hook_sceNpWebApiInitialize = {0};
static mh_hook_t g_hook_sceNpWebApiCreateRequest = {0};
static mh_hook_t g_hook_sceNpWebApiSendRequest2 = {0};
static mh_hook_t g_hook_sceKernelLoadStartModule = {0};

// IL2CPP hooks
static mh_hook_t g_hook_rustworks_get_root = {0};
static mh_hook_t g_hook_display_signin_dialog = {0};
static mh_hook_t g_hook_check_online_ps4 = {0};
static mh_hook_t g_hook_request_display_signon = {0};
static mh_hook_t g_hook_ps4_is_signed_in = {0};
static mh_hook_t g_hook_ps4_can_use_online = {0};
static mh_hook_t g_hook_ps4_user_has_mp_perm = {0};
static mh_hook_t g_hook_ps4_get_engaged_user_id = {0};
static mh_hook_t g_hook_frontend_is_engaged_signed_in = {0};
static mh_hook_t g_hook_getengageduser_movenext = {0};
static mh_hook_t g_hook_webrequest_set_url = {0};
static mh_hook_t g_hook_coroutine_check_online = {0};
static mh_hook_t g_hook_get_rustworks = {0};
static mh_hook_t g_hook_rustworks_initialise = {0};
static mh_hook_t g_hook_debug_log = {0};
static mh_hook_t g_hook_debug_log_error = {0};
static mh_hook_t g_hook_debug_log_warning = {0};
static mh_hook_t g_hook_debug_log_exception = {0};
static mh_hook_t g_hook_debug_is_debug_build = {0};
static mh_hook_t g_hook_webrequest_get_error = {0};
static mh_hook_t g_hook_rustworks_request_complete = {0};
static mh_hook_t g_hook_output_loghandler = {0};
static mh_hook_t g_hook_consoleui_log = {0};
static mh_hook_t g_hook_localserver_get_is_running = {0};
static mh_hook_t g_hook_dtls_startup = {0};
static mh_hook_t g_hook_dtls_get_isunencrypted = {0};
static mh_hook_t g_hook_createroom_wrapper = {0};
static mh_hook_t g_hook_leaveroom_wrapper = {0};
static mh_hook_t g_hook_searchrooms_wrapper = {0};
static mh_hook_t g_hook_joinroom_wrapper = {0};
static mh_hook_t g_hook_checkplus = {0};
static mh_hook_t g_hook_checkavailablity = {0};
static mh_hook_t g_hook_rustworks_connect = {0};
static mh_hook_t g_hook_findjoin_connect = {0};
static mh_hook_t g_hook_doserver_preconnect_movenext = {0};
static mh_hook_t g_hook_processserverpreconnect_movenext = {0};
static mh_hook_t g_hook_connecttoserver = {0};
static mh_hook_t g_hook_dtls_client_invalidpacket = {0};
static mh_hook_t g_hook_dtls_server_invalidpacket = {0};
static mh_hook_t g_hook_litenetlib_client_invalidpacket = {0};
static mh_hook_t g_hook_litenetlib_server_invalidpacket = {0};
static mh_hook_t g_hook_logger_writelog = {0};
static mh_hook_t g_hook_message_process = {0};
static mh_hook_t g_hook_on_request_user_info = {0};
static mh_hook_t g_hook_request_user_info_process = {0};
static mh_hook_t g_hook_on_approved = {0};
static mh_hook_t g_hook_client_cycle = {0};
static mh_hook_t g_hook_alienclient_start = {0};
static mh_hook_t g_hook_alienclient_readthread = {0};
static mh_hook_t g_hook_networkmessages_receive = {0};
static mh_hook_t g_hook_client_handle_message = {0};
static mh_hook_t g_hook_dtls_ssl_info_callback = {0};
static mh_hook_t g_hook_dtls_process_recv_buffer = {0};

// =============================================================================
// sceNp* hook functions - fake PSN API responses
// =============================================================================

int hook_sceNpGetAccountIdA(int userId, uint64_t *accountId) {
    if (accountId) {
        *accountId = 0x1234567890ABCDEFULL;
    }
    return 0;
}

int hook_sceNpWebApiInitialize(int httpCtxId, size_t poolSize) {
    return g_fake_lib_ctx++;
}

int hook_sceNpWebApiCreateContextA(int libCtxId, int userId) {
    return g_fake_web_ctx++;
}

int hook_sceNpWebApiCreateRequest(int ctxId, const char *hostPort, const char *path,
                                   int method, void *body, long *reqIdOut) {
    if (reqIdOut) {
        *reqIdOut = g_fake_request_id++;
    }
    return 0;
}

int hook_sceNpWebApiSendRequest2(long requestId, void *data, size_t dataLen, void *unknown) {
    return 0;
}

int hook_sceNpWebApiReadData(long requestId, void *buffer, size_t bufSize) {
    return 0;  // EOF
}

int hook_sceNpWebApiDeleteRequest(long requestId) {
    return 0;
}

// =============================================================================
// IL2CPP hook functions
// =============================================================================

// =============================================================================
// Debug logging hooks - capture Unity Debug.Log output
// =============================================================================
typedef void (*debug_log_orig_t)(void* message);
static debug_log_orig_t g_debug_log_original = NULL;
static debug_log_orig_t g_debug_log_error_original = NULL;
static debug_log_orig_t g_debug_log_warning_original = NULL;

typedef void (*debug_log_exception_orig_t)(void* exception);
static debug_log_exception_orig_t g_debug_log_exception_original = NULL;

// Helper to extract string from object (might be IL2CPP string or have ToString)
static void log_unity_message(const char* prefix, void* message) {
    if (!message) {
        final_printf("[UNITY %s] (null)\n", prefix);
        return;
    }

    // Try to read as IL2CPP string directly
    // Check if it looks like a valid string (has reasonable length)
    int len = *(int*)((char*)message + 0x10);
    if (len > 0 && len < 2000) {
        uint16_t* chars = (uint16_t*)((char*)message + 0x14);
        char buf[512];
        int i;
        for (i = 0; i < len && i < 511; i++) {
            buf[i] = (char)(chars[i] & 0xFF);
        }
        buf[i] = '\0';
        final_printf("[UNITY %s] %s\n", prefix, buf);
    } else {
        final_printf("[UNITY %s] (object at %p, len=%d)\n", prefix, message, len);
    }
}

void hook_debug_log(void* message) {
    log_unity_message("LOG", message);
    if (g_debug_log_original) {
        g_debug_log_original(message);
    }
}

void hook_debug_log_error(void* message) {
    log_unity_message("ERROR", message);
    if (g_debug_log_error_original) {
        g_debug_log_error_original(message);
    }
}

void hook_debug_log_warning(void* message) {
    log_unity_message("WARNING", message);
    if (g_debug_log_warning_original) {
        g_debug_log_warning_original(message);
    }
}

void hook_debug_log_exception(void* exception) {
    if (exception) {
        // Exception objects have Message at some offset, but structure varies
        // Just log that an exception occurred
        final_printf("[UNITY EXCEPTION] Exception object at %p\n", exception);

        // Try to get the message - typically at offset 0x10 or 0x18
        void* msg = *(void**)((char*)exception + 0x10);
        if (msg) {
            log_unity_message("EXCEPTION MSG", msg);
        }
    }
    if (g_debug_log_exception_original) {
        g_debug_log_exception_original(exception);
    }
}

// Hook Debug.isDebugBuild to always return true - enables debug features
typedef int (*debug_is_debug_build_orig_t)(void);
static debug_is_debug_build_orig_t g_debug_is_debug_build_original = NULL;

int hook_debug_is_debug_build(void) {
    static int logged = 0;
    if (!logged) {
        final_printf("[rust_psn_bypass] Debug.isDebugBuild hooked - returning true\n");
        logged = 1;
    }
    return 1;  // Always return true
}

// Hook UnityWebRequest.get_error() to log web errors
typedef void* (*webrequest_get_error_orig_t)(void* thisptr);
static webrequest_get_error_orig_t g_webrequest_get_error_original = NULL;

void* hook_webrequest_get_error(void* thisptr) {
    void* result = NULL;
    if (g_webrequest_get_error_original) {
        result = g_webrequest_get_error_original(thisptr);
    }

    // If there's an error string, log it
    if (result) {
        int len = *(int*)((char*)result + 0x10);
        if (len > 0 && len < 500) {
            uint16_t* chars = (uint16_t*)((char*)result + 0x14);
            char buf[256];
            int i;
            for (i = 0; i < len && i < 255; i++) {
                buf[i] = (char)(chars[i] & 0xFF);
            }
            buf[i] = '\0';
            final_printf("[WEBREQUEST ERROR] %s\n", buf);
        }
    }
    return result;
}

// Hook Rustworks.Request.Complete(string error) to log completion and errors
typedef void (*rustworks_request_complete_orig_t)(void* thisptr, void* error);
static rustworks_request_complete_orig_t g_rustworks_request_complete_original = NULL;

void hook_rustworks_request_complete(void* thisptr, void* error) {
    if (error) {
        int len = *(int*)((char*)error + 0x10);
        if (len > 0 && len < 500) {
            uint16_t* chars = (uint16_t*)((char*)error + 0x14);
            char buf[256];
            int i;
            for (i = 0; i < len && i < 255; i++) {
                buf[i] = (char)(chars[i] & 0xFF);
            }
            buf[i] = '\0';
            final_printf("[RUSTWORKS REQUEST COMPLETE] Error: %s\n", buf);
        } else {
            final_printf("[RUSTWORKS REQUEST COMPLETE] Error (invalid len=%d)\n", len);
        }
    } else {
        final_printf("[RUSTWORKS REQUEST COMPLETE] Success (no error)\n");
    }

    if (g_rustworks_request_complete_original) {
        g_rustworks_request_complete_original(thisptr, error);
    }
}

// =============================================================================
// Facepunch.Output.LogHandler - captures ALL Rust game log output
// =============================================================================
typedef void (*output_loghandler_orig_t)(void* log, void* stacktrace, int logType);
static output_loghandler_orig_t g_output_loghandler_original = NULL;

void hook_output_loghandler(void* log, void* stacktrace, int logType) {
    // LogType: 0=Error, 1=Assert, 2=Warning, 3=Log, 4=Exception
    const char* typeStr = "???";
    switch (logType) {
        case 0: typeStr = "ERROR"; break;
        case 1: typeStr = "ASSERT"; break;
        case 2: typeStr = "WARN"; break;
        case 3: typeStr = "LOG"; break;
        case 4: typeStr = "EXCEPTION"; break;
    }

    if (log) {
        int len = *(int*)((char*)log + 0x10);
        if (len > 0 && len < 1000) {
            uint16_t* chars = (uint16_t*)((char*)log + 0x14);
            char buf[512];
            int i;
            for (i = 0; i < len && i < 511; i++) {
                buf[i] = (char)(chars[i] & 0xFF);
            }
            buf[i] = '\0';
            final_printf("[RUST %s] %s\n", typeStr, buf);
        }
    }

    if (g_output_loghandler_original) {
        g_output_loghandler_original(log, stacktrace, logType);
    }
}

// =============================================================================
// ConsoleUI.Log - captures console output
// =============================================================================
typedef void (*consoleui_log_orig_t)(void* thisptr, void* message);
static consoleui_log_orig_t g_consoleui_log_original = NULL;

void hook_consoleui_log(void* thisptr, void* message) {
    if (message) {
        int len = *(int*)((char*)message + 0x10);
        if (len > 0 && len < 1000) {
            uint16_t* chars = (uint16_t*)((char*)message + 0x14);
            char buf[512];
            int i;
            for (i = 0; i < len && i < 511; i++) {
                buf[i] = (char)(chars[i] & 0xFF);
            }
            buf[i] = '\0';
            final_printf("[CONSOLE] %s\n", buf);
        }
    }

    if (g_consoleui_log_original) {
        g_consoleui_log_original(thisptr, message);
    }
}

// =============================================================================
// DTLS.Client.InvalidPacket - debug packet rejection
// =============================================================================
typedef int (*dtls_client_invalidpacket_orig_t)(void* thisptr, uint8_t type);
static dtls_client_invalidpacket_orig_t g_dtls_client_invalidpacket_original = NULL;

int hook_dtls_client_invalidpacket(void* thisptr, uint8_t type) {
    final_printf("[DTLS CLIENT] InvalidPacket called! type=0x%02x\n", type);

    int result = 0;
    if (g_dtls_client_invalidpacket_original) {
        result = g_dtls_client_invalidpacket_original(thisptr, type);
    }

    final_printf("[DTLS CLIENT] InvalidPacket returning: %d (1=invalid, 0=valid)\n", result);
    return result;
}

// =============================================================================
// DTLS.Server.InvalidPacket - debug packet rejection
// =============================================================================
typedef int (*dtls_server_invalidpacket_orig_t)(void* thisptr, uint8_t type, void* connection);
static dtls_server_invalidpacket_orig_t g_dtls_server_invalidpacket_original = NULL;

int hook_dtls_server_invalidpacket(void* thisptr, uint8_t type, void* connection) {
    final_printf("[DTLS SERVER] InvalidPacket called! type=0x%02x connection=%p\n", type, connection);

    int result = 0;
    if (g_dtls_server_invalidpacket_original) {
        result = g_dtls_server_invalidpacket_original(thisptr, type, connection);
    }

    final_printf("[DTLS SERVER] InvalidPacket returning: %d (1=invalid, 0=valid)\n", result);
    return result;
}

// =============================================================================
// LiteNetLib.Client.InvalidPacket - debug packet rejection at LiteNetLib layer
// =============================================================================
typedef int (*litenetlib_client_invalidpacket_orig_t)(void* thisptr, uint8_t type);
static litenetlib_client_invalidpacket_orig_t g_litenetlib_client_invalidpacket_original = NULL;

int hook_litenetlib_client_invalidpacket(void* thisptr, uint8_t type) {
    final_printf("[LITENETLIB CLIENT] InvalidPacket called! type=0x%02x\n", type);

    int result = 0;
    if (g_litenetlib_client_invalidpacket_original) {
        result = g_litenetlib_client_invalidpacket_original(thisptr, type);
    }

    final_printf("[LITENETLIB CLIENT] InvalidPacket returning: %d (1=invalid, 0=valid)\n", result);
    return result;
}

// =============================================================================
// LiteNetLib.Server.InvalidPacket - debug packet rejection at LiteNetLib layer
// =============================================================================
typedef int (*litenetlib_server_invalidpacket_orig_t)(void* thisptr, uint8_t type, void* connection);
static litenetlib_server_invalidpacket_orig_t g_litenetlib_server_invalidpacket_original = NULL;

int hook_litenetlib_server_invalidpacket(void* thisptr, uint8_t type, void* connection) {
    final_printf("[LITENETLIB SERVER] InvalidPacket called! type=0x%02x connection=%p\n", type, connection);

    int result = 0;
    if (g_litenetlib_server_invalidpacket_original) {
        result = g_litenetlib_server_invalidpacket_original(thisptr, type, connection);
    }

    final_printf("[LITENETLIB SERVER] InvalidPacket returning: %d (1=invalid, 0=valid)\n", result);
    return result;
}

// =============================================================================
// D11.Logger.WriteLog - captures all DTLS logging
// =============================================================================
typedef void (*logger_writelog_orig_t)(int32_t category, int32_t level, void* tag, void* message, void* args);
static logger_writelog_orig_t g_logger_writelog_original = NULL;

void hook_logger_writelog(int32_t category, int32_t level, void* tag, void* message, void* args) {
    // Extract IL2CPP strings (format: [klass 8][monitor 8][length 4][chars UTF-16LE])
    char tag_str[128] = {0};
    char msg_str[512] = {0};

    if (tag) {
        int tag_len = *(int32_t*)((char*)tag + 0x10);
        if (tag_len > 0 && tag_len < 127) {
            uint16_t* tag_chars = (uint16_t*)((char*)tag + 0x14);
            for (int i = 0; i < tag_len; i++) {
                tag_str[i] = (char)(tag_chars[i] & 0xFF);
            }
        }
    }

    if (message) {
        int msg_len = *(int32_t*)((char*)message + 0x10);
        if (msg_len > 0 && msg_len < 511) {
            uint16_t* msg_chars = (uint16_t*)((char*)message + 0x14);
            for (int i = 0; i < msg_len; i++) {
                msg_str[i] = (char)(msg_chars[i] & 0xFF);
            }
        }
    }

    // Color codes: Level 0=Cyan, 1=Green, 2=Yellow, 3+=Red
    const char* color = "\033[36m";  // Cyan for debug
    const char* level_name = "DEBUG";
    if (level == 1) {
        color = "\033[32m";  // Green for info
        level_name = "INFO ";
    } else if (level == 2) {
        color = "\033[33m";  // Yellow for warning
        level_name = "WARN ";
    } else if (level >= 3) {
        color = "\033[31m";  // Red for error
        level_name = "ERROR";
    }

    final_printf("%s[DTLS:%s] [%s] %s\033[0m\n", color, level_name, tag_str, msg_str);

    // Call original
    if (g_logger_writelog_original) {
        g_logger_writelog_original(category, level, tag, message, args);
    }
}

// =============================================================================
// Network Message Handler Hooks - for debugging game protocol
// =============================================================================
typedef void (*message_handler_orig_t)(void* thisptr, void* packet);
static message_handler_orig_t g_message_process_original = NULL;
static message_handler_orig_t g_on_request_user_info_original = NULL;
static message_handler_orig_t g_request_user_info_process_original = NULL;
static message_handler_orig_t g_on_approved_original = NULL;

void hook_message_process(void* thisptr, void* packet) {
    final_printf("[RUST] \033[35m*** MessageProcess called ***\033[0m\n");

    if (g_message_process_original) {
        g_message_process_original(thisptr, packet);
    }
}

void hook_on_request_user_info(void* thisptr, void* packet) {
    final_printf("[RUST] \033[36m*** OnRequestUserInformation called ***\033[0m\n");

    if (g_on_request_user_info_original) {
        g_on_request_user_info_original(thisptr, packet);
    }
}

void hook_request_user_info_process(void* thisptr, void* packet) {
    final_printf("[RUST] \033[32m*** RequestUserInformationProcess called ***\033[0m\n");

    if (g_request_user_info_process_original) {
        g_request_user_info_process_original(thisptr, packet);
    }
}

void hook_on_approved(void* thisptr, void* packet) {
    final_printf("[RUST] \033[33m*** OnApproved called ***\033[0m\n");

    if (g_on_approved_original) {
        g_on_approved_original(thisptr, packet);
    }
}

typedef void (*client_cycle_orig_t)(void* thisptr);
typedef void (*client_handle_message_orig_t)(void* thisptr);
typedef void (*networkmessages_receive_orig_t)(void* thisptr, void* socket, void* message_ref);
typedef void (*alienclient_start_orig_t)(void* thisptr);
typedef void (*alienclient_readthread_orig_t)(void* thisptr);
typedef void (*dtls_process_recv_buffer_orig_t)(void* thisptr);
static client_cycle_orig_t g_client_cycle_original = NULL;
static client_handle_message_orig_t g_client_handle_message_original = NULL;
static networkmessages_receive_orig_t g_networkmessages_receive_original = NULL;
static alienclient_start_orig_t g_alienclient_start_original = NULL;
static alienclient_readthread_orig_t g_alienclient_readthread_original = NULL;
static dtls_process_recv_buffer_orig_t g_dtls_process_recv_buffer_original = NULL;

void hook_client_cycle(void* thisptr) {
    // Don't log every frame - too spammy
    // final_printf("[CLIENT] \033[90mCycle() called\033[0m\n");

    if (g_client_cycle_original) {
        g_client_cycle_original(thisptr);
    }
}

void hook_alienclient_start(void* thisptr) {
    final_printf("[ALIENCLIENT] \033[92m*** Start() called - Starting read/write threads ***\033[0m\n");

    if (g_alienclient_start_original) {
        g_alienclient_start_original(thisptr);
    }
}

void hook_alienclient_readthread(void* thisptr) {
    final_printf("[ALIENCLIENT] \033[96m*** ReadThread() started ***\033[0m\n");

    if (g_alienclient_readthread_original) {
        g_alienclient_readthread_original(thisptr);
    }
}

void hook_networkmessages_receive(void* thisptr, void* socket, void* message_ref) {
    final_printf("[NETWORKMESSAGES] \033[93m*** ReceiveMessage called (Socket.Receive) ***\033[0m\n");

    if (g_networkmessages_receive_original) {
        g_networkmessages_receive_original(thisptr, socket, message_ref);
    }
}

// Track if handlers get invoked after ProcessRecvBuffer
static int g_process_recv_buffer_called = 0;
static int g_handler_invoked_after_process = 0;
static int g_dtls_messages_found_total = 0;

void hook_dtls_process_recv_buffer(void* thisptr) {
    // Get connection ID from thisptr+0x10 (based on decompilation)
    uint32_t conn_id = *(uint32_t*)((char*)thisptr + 0x10);

    g_process_recv_buffer_called++;
    int prev_handler_count = g_handler_invoked_after_process;

    if (g_dtls_process_recv_buffer_original) {
        g_dtls_process_recv_buffer_original(thisptr);
    }

    // Check if handler was invoked during this call
    int handlers_this_call = g_handler_invoked_after_process - prev_handler_count;
    if (handlers_this_call > 0) {
        g_dtls_messages_found_total += handlers_this_call;
    }

    // Only log once per second to avoid spam
    static uint64_t last_log_time = 0;
    uint64_t current_time = sceKernelGetProcessTime();
    if (current_time - last_log_time > 1000000) { // 1 second in microseconds
        final_printf("[DTLS] ProcessRecvBuffer connID=%u | Calls: %d | Handlers: %d | Total msgs: %d | Rate: %.1f%%\n",
                    conn_id, g_process_recv_buffer_called, g_handler_invoked_after_process, g_dtls_messages_found_total,
                    g_process_recv_buffer_called > 0 ? (100.0 * g_handler_invoked_after_process / g_process_recv_buffer_called) : 0.0);
        last_log_time = current_time;
    }

    // Log the first time we actually find a message
    static int first_message_logged = 0;
    if (handlers_this_call > 0 && !first_message_logged) {
        final_printf("[DTLS] \033[92m*** FIRST MESSAGE FOUND! Handler called %d times ***\033[0m\n", handlers_this_call);
        first_message_logged = 1;
    }
}

void hook_client_handle_message(void* thisptr) {
    g_handler_invoked_after_process++;
    final_printf("[CLIENT] \033[94m*** HandleMessage called (count: %d) ***\033[0m\n", g_handler_invoked_after_process);

    if (g_client_handle_message_original) {
        g_client_handle_message_original(thisptr);
    }
}

// =============================================================================
// DTLS SSL Handshake Hook - monitor handshake state
// =============================================================================
typedef void (*dtls_ssl_info_callback_orig_t)(void* param_1, void* param_2, uint64_t flags, int param_4);
static dtls_ssl_info_callback_orig_t g_dtls_ssl_info_callback_original = NULL;

void hook_dtls_ssl_info_callback(void* param_1, void* param_2, uint64_t flags, int param_4) {
    // Check for handshake events
    if (flags & 0x10) {
        final_printf("\033[93m[DTLS HANDSHAKE] *** HANDSHAKE START ***\033[0m\n");
    }
    if (flags & 0x20) {
        final_printf("\033[92m[DTLS HANDSHAKE] *** HANDSHAKE DONE ***\033[0m\n");
    }

    // Call original
    if (g_dtls_ssl_info_callback_original) {
        g_dtls_ssl_info_callback_original(param_1, param_2, flags, param_4);
    }
}

// Rustworks.get_Root() - API redirection
// IL2CPP string layout: [klass ptr 8][monitor ptr 8][length 4][chars... (UTF-16LE)]
typedef void* (*get_root_orig_t)(void* thisptr);
static get_root_orig_t g_get_root_original = NULL;

// Custom server URL - change this to your server
#define CUSTOM_API_URL "http://192.168.1.100:8080"

void* hook_rustworks_get_root(void* thisptr) {
    static int call_count = 0;
    call_count++;

    // Log every call for debugging
    if (call_count <= 5) {
        final_printf("[rust_psn_bypass] get_Root called #%d, thisptr=%p\n", call_count, thisptr);
    }

    void* original_string = NULL;
    if (g_get_root_original) {
        original_string = g_get_root_original(thisptr);
    }

    if (call_count <= 5) {
        final_printf("[rust_psn_bypass] get_Root result=%p\n", original_string);
    }

    // Log the original Root URL for debugging
    if (original_string) {
        // IL2CPP string: offset 0x10 = length (int32), offset 0x14 = chars (UTF-16LE)
        int len = *(int*)((char*)original_string + 0x10);
        uint16_t* chars = (uint16_t*)((char*)original_string + 0x14);

        // Convert first 64 chars to ASCII for logging
        char buf[65];
        int i;
        for (i = 0; i < len && i < 64; i++) {
            buf[i] = (char)(chars[i] & 0xFF);
        }
        buf[i] = '\0';

        static int logged = 0;
        if (!logged) {
            final_printf("[rust_psn_bypass] Rustworks.Root = %s (len=%d)\n", buf, len);
            logged = 1;
        }
    }

    return original_string;
}

// UnityWebRequest.InternalSetUrl - intercept and log/redirect URLs
typedef void (*internal_set_url_orig_t)(void* thisptr, void* url_string);
static internal_set_url_orig_t g_internal_set_url_original = NULL;

// Custom server configuration - CHANGE THIS TO YOUR SERVER
#define CUSTOM_SERVER_HOST "192.168.0.111"  // Your server IP
#define CUSTOM_SERVER_PORT "9000"

// Helper to convert IL2CPP string to C string
static void il2cpp_string_to_cstr(void* il2cpp_str, char* buf, int bufsize) {
    if (!il2cpp_str || !buf || bufsize < 1) {
        if (buf) buf[0] = '\0';
        return;
    }
    int len = *(int*)((char*)il2cpp_str + 0x10);
    uint16_t* chars = (uint16_t*)((char*)il2cpp_str + 0x14);
    int i;
    for (i = 0; i < len && i < bufsize - 1; i++) {
        buf[i] = (char)(chars[i] & 0xFF);
    }
    buf[i] = '\0';
}

// Helper to modify IL2CPP string in-place (write new URL over existing chars)
// Returns 1 on success, 0 if new URL doesn't fit
static int il2cpp_string_replace(void* il2cpp_str, const char* new_url) {
    if (!il2cpp_str || !new_url) return 0;

    int orig_len = *(int*)((char*)il2cpp_str + 0x10);
    int new_len = strlen(new_url);

    // SAFETY: Only replace if new URL fits in original buffer
    // Writing past the allocation corrupts memory and causes crashes
    if (new_len > orig_len) {
        final_printf("[rust_psn_bypass] WARNING: new URL too long (%d > %d), skipping redirect\n", new_len, orig_len);
        return 0;
    }

    uint16_t* chars = (uint16_t*)((char*)il2cpp_str + 0x14);

    // Write new URL as UTF-16LE
    for (int i = 0; i < new_len; i++) {
        chars[i] = (uint16_t)(unsigned char)new_url[i];
    }

    // Update length field
    *(int*)((char*)il2cpp_str + 0x10) = new_len;
    return 1;
}

// Check if URL contains a substring
static int url_contains(const char* url, const char* substr) {
    return strstr(url, substr) != NULL;
}

void hook_webrequest_internal_set_url(void* thisptr, void* url_string) {
    static int log_count = 0;

    if (!url_string) {
        if (g_internal_set_url_original) {
            g_internal_set_url_original(thisptr, url_string);
        }
        return;
    }

    // Capture string klass pointer for creating fake strings later
    capture_string_klass(url_string);

    char url_buf[512];
    il2cpp_string_to_cstr(url_string, url_buf, sizeof(url_buf));

    // Log first 100 requests
    if (log_count < 100) {
        final_printf("[rust_psn_bypass] WebRequest URL: %s\n", url_buf);
        log_count++;
    }

    // Check if this is a rustworks.net URL that we want to redirect
    if (url_contains(url_buf, "rustworks.net")) {
        char* path_start = strstr(url_buf, "rustworks.net");
        if (path_start) {
            path_start = strchr(path_start, '/');
            if (!path_start) path_start = "";

            char new_url[512];
            snprintf(new_url, sizeof(new_url), "http://%s:%s%s",
                     CUSTOM_SERVER_HOST, CUSTOM_SERVER_PORT, path_start);

            final_printf("[rust_psn_bypass] Redirecting to: %s\n", new_url);
            il2cpp_string_replace(url_string, new_url);
        }
    }
    // Also redirect localhost requests (server list uses localhost as placeholder)
    // NOTE: These are short URLs so we can't do in-place replacement
    // Skip redirect if URL is too short - the request will fail but won't crash
    else if (url_contains(url_buf, "://localhost/") || url_contains(url_buf, "://localhost:")) {
        char* path_start = strstr(url_buf, "localhost");
        if (path_start) {
            path_start = strchr(path_start, '/');
            if (!path_start) path_start = "";

            char new_url[512];
            snprintf(new_url, sizeof(new_url), "http://%s:%s%s",
                     CUSTOM_SERVER_HOST, CUSTOM_SERVER_PORT, path_start);

            // Only redirect if it fits - don't crash trying to create new strings
            int orig_len = *(int*)((char*)url_string + 0x10);
            int new_len = strlen(new_url);

            if (new_len <= orig_len) {
                final_printf("[rust_psn_bypass] Redirecting localhost to: %s\n", new_url);
                il2cpp_string_replace(url_string, new_url);
            } else {
                final_printf("[rust_psn_bypass] Cannot redirect localhost (need %d chars, have %d) - skipping\n", new_len, orig_len);
            }
        }
    }

    // Call original with (possibly modified) URL
    if (g_internal_set_url_original) {
        g_internal_set_url_original(thisptr, url_string);
    }
}

// NpUtils.DisplaySigninDialog - bypass PSN sign-in dialog
int hook_display_signin_dialog(void* request, void* response) {
    if (response) {
        *(int*)((char*)response + 0x10) = 0;      // returnCode = success
        *(char*)((char*)response + 0x14) = 0;     // locked = false
        *(void**)((char*)response + 0x18) = NULL; // serverError = null
    }
    return 1;
}

// ButtonMainMenu.CheckOnline_PS4 - skip online check
void* hook_check_online_ps4(void* thisptr) {
    return NULL;  // Return NULL to skip coroutine
}

// PlatformServicesPS4.RequestDisplaySignOnDialog - return pre-completed request
typedef void* (*request_display_signon_orig_t)(void* thisptr);
static request_display_signon_orig_t g_request_display_signon_original = NULL;

void* hook_request_display_signon(void* thisptr) {
    void* request = NULL;
    if (g_request_display_signon_original) {
        request = g_request_display_signon_original(thisptr);
    }
    if (request) {
        *(char*)((char*)request + 0x10) = 1;   // IsComplete = true
        *(char*)((char*)request + 0x11) = 0;   // Cancelled = false
        *(int*)((char*)request + 0x18) = 0;    // ErrorCode = 0
    }
    return request;
}

// PlatformServicesPS4.IsSignedIn - always return true
int hook_ps4_is_signed_in(void* thisptr) {
    return 1;
}

// PlatformServicesPS4.CanUseOnline - always return true
int hook_ps4_can_use_online(void* thisptr) {
    return 1;
}

// PlatformServicesPS4.UserHasMultiplayerPermission - return pre-completed success
typedef void* (*user_has_mp_perm_orig_t)(void* thisptr);
static user_has_mp_perm_orig_t g_user_has_mp_perm_original = NULL;

void* hook_ps4_user_has_mp_perm(void* thisptr) {
    void* request = NULL;
    if (g_user_has_mp_perm_original) {
        request = g_user_has_mp_perm_original(thisptr);
    }
    if (request) {
        *(char*)((char*)request + 0x10) = 1;   // IsComplete = true
        *(char*)((char*)request + 0x11) = 0;   // Cancelled = false
        *(int*)((char*)request + 0x18) = 0;    // ErrorCode = 0
    }
    return request;
}

// PlatformServicesPS4.GetEngagedUserID - return valid user ID
int hook_ps4_get_engaged_user_id(void* thisptr) {
    return FAKE_USER_ID;
}

// Rustworks.Initialise - intercept initialization and set our custom Root URL
// Signature: ILoginRequest Initialise(this, string root, string metricsRoot, int networkProtocol)
typedef void* (*rustworks_initialise_orig_t)(void* thisptr, void* root, void* metricsRoot, int networkProtocol);
static rustworks_initialise_orig_t g_rustworks_initialise_original = NULL;

void* hook_rustworks_initialise(void* thisptr, void* root, void* metricsRoot, int networkProtocol) {
    final_printf("[rust_psn_bypass] Rustworks.Initialise called!\n");
    final_printf("[rust_psn_bypass]   thisptr=%p, root=%p, metricsRoot=%p, networkProtocol=%d\n",
                 thisptr, root, metricsRoot, networkProtocol);

    // Log original Root URL
    if (root) {
        char buf[256];
        il2cpp_string_to_cstr(root, buf, sizeof(buf));
        final_printf("[rust_psn_bypass]   Original Root: %s\n", buf);

        // Patch the root URL in-place to our custom server
        char new_root[256];
        snprintf(new_root, sizeof(new_root), "http://%s:%s", CUSTOM_SERVER_HOST, CUSTOM_SERVER_PORT);
        if (il2cpp_string_replace(root, new_root)) {
            final_printf("[rust_psn_bypass]   Patched Root to: %s\n", new_root);
        }
    } else {
        final_printf("[rust_psn_bypass]   Root is NULL!\n");
    }

    // Log original MetricsRoot URL
    if (metricsRoot) {
        char buf[256];
        il2cpp_string_to_cstr(metricsRoot, buf, sizeof(buf));
        final_printf("[rust_psn_bypass]   Original MetricsRoot: %s\n", buf);
    }

    // Call original Initialise with (possibly patched) root
    void* result = NULL;
    if (g_rustworks_initialise_original) {
        result = g_rustworks_initialise_original(thisptr, root, metricsRoot, networkProtocol);
    }

    final_printf("[rust_psn_bypass]   Initialise returned: %p\n", result);

    // After Initialise, the Rustworks object should have Root set at offset 0x40
    // Also set UserId since we're here
    *(uint64_t*)((char*)thisptr + 0x58) = 0x123456789ABCDEFULL;
    final_printf("[rust_psn_bypass]   Set UserId to fake value\n");

    return result;
}

// PlatformServices.get_Rustworks - patch UserId and Root fields on returned object
typedef void* (*get_rustworks_orig_t)(int unused);
static get_rustworks_orig_t g_get_rustworks_original = NULL;

// Helper to create a new IL2CPP string by modifying an existing one in place
// We use this to patch the Root URL to point to our custom server
static void patch_rustworks_root(void* rustworks) {
    // Rustworks object layout:
    // offset 0x40 = Root (string) - base API URL
    // offset 0x48 = MetricsRoot (string)
    void* root_string = *(void**)((char*)rustworks + 0x40);

    if (!root_string) {
        final_printf("[rust_psn_bypass] Root string is NULL\n");
        return;
    }

    // Get current Root URL
    int len = *(int*)((char*)root_string + 0x10);
    uint16_t* chars = (uint16_t*)((char*)root_string + 0x14);

    char current_root[256];
    int i;
    for (i = 0; i < len && i < 255; i++) {
        current_root[i] = (char)(chars[i] & 0xFF);
    }
    current_root[i] = '\0';

    final_printf("[rust_psn_bypass] Current Root URL: %s (len=%d)\n", current_root, len);

    // Build our custom server URL
    char new_root[256];
    snprintf(new_root, sizeof(new_root), "http://%s:%s", CUSTOM_SERVER_HOST, CUSTOM_SERVER_PORT);
    int new_len = strlen(new_root);

    // Check if we have enough space
    if (new_len > len) {
        final_printf("[rust_psn_bypass] WARNING: Custom URL too long (%d > %d), cannot patch Root\n", new_len, len);
        return;
    }

    // Write new URL
    for (i = 0; i < new_len; i++) {
        chars[i] = (uint16_t)(unsigned char)new_root[i];
    }
    *(int*)((char*)root_string + 0x10) = new_len;

    final_printf("[rust_psn_bypass] Patched Root URL to: %s\n", new_root);
}

// Helper to create a fake IL2CPP string by reusing an existing string's buffer
// We'll write "fake_token" into any existing string buffer that's long enough
static void set_fake_access_token(void* rustworks) {
    void* access_token = *(void**)((char*)rustworks + 0x38);

    // If there's already an access token string, patch it
    // If not, we need to borrow another string - use the Root string as template
    void* root_string = *(void**)((char*)rustworks + 0x40);

    if (access_token) {
        // There's already a token string - check its length
        int len = *(int*)((char*)access_token + 0x10);
        final_printf("[rust_psn_bypass] Existing access_token length: %d\n", len);

        // Write "fake_token_12345" (16 chars)
        const char* fake = "fake_token_12345";
        int new_len = 16;

        if (len >= new_len) {
            uint16_t* chars = (uint16_t*)((char*)access_token + 0x14);
            for (int i = 0; i < new_len; i++) {
                chars[i] = (uint16_t)(unsigned char)fake[i];
            }
            *(int*)((char*)access_token + 0x10) = new_len;
            final_printf("[rust_psn_bypass] Patched existing access_token to: %s\n", fake);
        } else {
            final_printf("[rust_psn_bypass] access_token too short (%d), cannot patch\n", len);
        }
    } else if (root_string) {
        // No access token yet - we need to point it to some valid string
        // We can't easily allocate new IL2CPP strings, so we'll try using the Root string
        // This is a hack - the token will have the same content as Root initially
        // But at least the pointer won't be NULL
        final_printf("[rust_psn_bypass] No access_token, setting to Root string pointer\n");
        *(void**)((char*)rustworks + 0x38) = root_string;
    } else {
        final_printf("[rust_psn_bypass] No access_token and no Root string to borrow\n");
    }
}

// Global pointer to cached Rustworks instance so we can call Initialise
static void* g_rustworks_instance = NULL;
static int g_initialise_called = 0;

// Fake IL2CPP string buffer for Root URL
// IL2CPP string layout: [klass ptr 8][monitor ptr 8][length 4 at 0x10][chars at 0x14 (UTF-16LE)]
// We need: 8 + 8 + 4 + (max_url_len * 2) bytes
// For "http://192.168.0.111:9000" (25 chars) we need 8+8+4+50 = 70 bytes, round up to 128
static char g_fake_root_string[128] __attribute__((aligned(16)));
static char g_fake_token_string[128] __attribute__((aligned(16)));
static int g_fake_strings_initialized = 0;

// Captured klass pointer from a real IL2CPP string
static void* g_string_klass_ptr = NULL;

// Capture the klass pointer from a real IL2CPP string
static void capture_string_klass(void* il2cpp_str) {
    if (g_string_klass_ptr != NULL) return;  // Already captured
    if (il2cpp_str == NULL) return;

    void* klass = *(void**)il2cpp_str;
    if (klass != NULL) {
        g_string_klass_ptr = klass;
        final_printf("[rust_psn_bypass] Captured string klass pointer: %p\n", klass);
    }
}

// Initialize a fake IL2CPP string with ASCII content
// Uses captured klass pointer if available for compatibility
static void* create_fake_il2cpp_string(char* buffer, const char* content) {
    int len = strlen(content);

    // Clear buffer
    memset(buffer, 0, 128);

    // klass ptr at 0x00 - use captured klass if available
    *(void**)(buffer + 0x00) = g_string_klass_ptr;  // May be NULL if not captured yet

    // monitor ptr at 0x08 - set to NULL
    *(void**)(buffer + 0x08) = NULL;

    // length at 0x10
    *(int*)(buffer + 0x10) = len;

    // chars at 0x14 (UTF-16LE)
    uint16_t* chars = (uint16_t*)(buffer + 0x14);
    for (int i = 0; i < len; i++) {
        chars[i] = (uint16_t)(unsigned char)content[i];
    }

    return buffer;
}

void* hook_get_rustworks(int unused) {
    static int call_count = 0;
    static int root_patched = 0;
    call_count++;

    void* rustworks = NULL;
    if (g_get_rustworks_original) {
        rustworks = g_get_rustworks_original(unused);
    }

    if (rustworks) {
        g_rustworks_instance = rustworks;

        // Rustworks object layout:
        // offset 0x38 = accessToken (string) - auth token
        // offset 0x40 = Root (string) - base API URL
        // offset 0x48 = MetricsRoot (string)
        // offset 0x50 = NetworkProtocol (int)
        // offset 0x58 = UserId (ulong)

        // Patch UserId if zero
        uint64_t current_id = *(uint64_t*)((char*)rustworks + 0x58);
        if (current_id == 0) {
            // Set a fake non-zero UserId
            *(uint64_t*)((char*)rustworks + 0x58) = 0x123456789ABCDEFULL;

            if (call_count <= 10) {
                final_printf("[rust_psn_bypass] get_Rustworks: patched UserId from 0 to fake ID\n");
            }
        }

        // Check if Root is set
        void* root_string = *(void**)((char*)rustworks + 0x40);

        // Try to capture string klass from existing strings
        if (root_string) {
            capture_string_klass(root_string);
        }
        void* token_string = *(void**)((char*)rustworks + 0x38);
        if (token_string) {
            capture_string_klass(token_string);
        }

        if (root_string) {
            // Root is set - Initialise was called
            // Patch Root URL (only once)
            if (!root_patched) {
                patch_rustworks_root(rustworks);
                root_patched = 1;
            }
        } else {
            // Root is NULL - Initialise was never called
            // Create fake strings and set them directly
            if (!root_patched) {
                final_printf("[rust_psn_bypass] Root is NULL - creating fake IL2CPP strings\n");
                final_printf("[rust_psn_bypass] Using string klass pointer: %p\n", g_string_klass_ptr);

                // Build our custom server URL
                char url[64];
                snprintf(url, sizeof(url), "http://%s:%s", CUSTOM_SERVER_HOST, CUSTOM_SERVER_PORT);

                // Create fake Root string
                void* fake_root = create_fake_il2cpp_string(g_fake_root_string, url);

                // Create fake accessToken string
                void* fake_token = create_fake_il2cpp_string(g_fake_token_string, "fake_access_token_12345");

                // Set Root (offset 0x40)
                *(void**)((char*)rustworks + 0x40) = fake_root;

                // Set MetricsRoot to same URL (offset 0x48)
                *(void**)((char*)rustworks + 0x48) = fake_root;

                // Set accessToken (offset 0x38)
                *(void**)((char*)rustworks + 0x38) = fake_token;

                // Set NetworkProtocol (offset 0x50) - usually 0 or 1
                *(int*)((char*)rustworks + 0x50) = 1;

                root_patched = 1;
                g_fake_strings_initialized = 1;

                final_printf("[rust_psn_bypass] Set fake Root URL: %s\n", url);
                final_printf("[rust_psn_bypass] Set fake accessToken\n");
                final_printf("[rust_psn_bypass] fake_root ptr: %p, fake_token ptr: %p\n", fake_root, fake_token);
            }
        }
    }

    return rustworks;
}

// FindJoinGameUI.<Coroutine_CheckOnline>d__97.MoveNext - force success result
// We completely bypass the coroutine by:
// 1. First call (state 0): Set state to 4, return 1 (yield)
// 2. Second call (state 4): Set state to -1, return 0 (done)
// The <>2__current at offset 0x18 needs to be a boxed true - we fake it
int hook_coroutine_check_online_movenext(void* thisptr) {
    static int call_count = 0;
    call_count++;

    int state = *(int*)((char*)thisptr + 0x10);

    if (call_count <= 10) {
        final_printf("[rust_psn_bypass] Coroutine_CheckOnline.MoveNext #%d, state=%d\n", call_count, state);
    }

    // State machine:
    // State 0 -> we set to 4 and return 1 (keep running)
    // State 4 -> we set to -1 and return 0 (done)
    //
    // The caller checks DataCoroutine.Result which comes from <>2__current
    // But DataCoroutine<bool> stores the result differently - at offset 0x10 of the DataCoroutine object
    // The parent coroutine stores DataCoroutine at offset 0x30

    if (state == 0 || state == 1 || state == 2 || state == 3) {
        // Force to state 4 (success exit)
        *(int*)((char*)thisptr + 0x10) = 4;
        // Set <>2__current to NULL - it's an object pointer field, not a value
        // Setting to 1 causes crash when code tries to dereference it as pointer
        *(uint64_t*)((char*)thisptr + 0x18) = 0;

        if (call_count <= 10) {
            final_printf("[rust_psn_bypass] Forcing state 4, returning 1 (yield)\n");
        }
        return 1;  // yield once
    }
    else if (state == 4) {
        // Now complete
        *(int*)((char*)thisptr + 0x10) = -1;

        if (call_count <= 10) {
            final_printf("[rust_psn_bypass] State 4 -> done, returning 0\n");
        }
        return 0;  // done
    }

    // Already done
    return 0;
}

// FrontendUI.IsEngagedUserSignedIn - always return true
int hook_frontend_is_engaged_signed_in(void* thisptr) {
    return 1;
}

// LocalServer.get_isRunningLocalServer - return true to enable local server mode
// Original function is just: XOR EAX, EAX; RET (always returns false)
int hook_localserver_get_is_running(void) {
    static int logged = 0;
    if (!logged) {
        final_printf("[rust_psn_bypass] LocalServer.get_isRunningLocalServer hooked - returning true\n");
        logged = 1;
    }
    return 1;  // Enable local server mode
}

// DTLS.Startup hook - force unencrypted mode for PC server compatibility
// This is called by Facepunch.Network.DTLS.Client.Connect
// Signature: void Startup(DTLS* this, bool isServer, string serverAddress, int serverPort, string cipherList, string cipherSuites, bool isUnencrypted)
typedef void (*dtls_startup_orig_t)(void* thisptr, int isServer, void* serverAddress, int serverPort, void* cipherList, void* cipherSuites, int isUnencrypted);
static dtls_startup_orig_t g_dtls_startup_original = NULL;

void hook_dtls_startup(void* thisptr, int isServer, void* serverAddress, int serverPort, void* cipherList, void* cipherSuites, int isUnencrypted) {
    final_printf("[rust_psn_bypass] DTLS.Startup called: isServer=%d, port=%d, isUnencrypted=%d\n", isServer, serverPort, isUnencrypted);

    // Log server address if present
    if (serverAddress) {
        int len = *(int*)((char*)serverAddress + 0x10);
        if (len > 0 && len < 100) {
            uint16_t* chars = (uint16_t*)((char*)serverAddress + 0x14);
            char buf[100];
            int i;
            for (i = 0; i < len && i < 99; i++) {
                buf[i] = (char)(chars[i] & 0xFF);
            }
            buf[i] = '\0';
            final_printf("[rust_psn_bypass] DTLS connecting to: %s:%d\n", buf, serverPort);
        }
    }

    // Force unencrypted mode regardless of what was passed
    final_printf("[rust_psn_bypass] Forcing isUnencrypted=TRUE for custom server compatibility\n");

    // Try to enable DTLS native logging - find DTLS.prx if not already found
    if (g_dtls_prx_base_address == 0) {
        final_printf("[rust_psn_bypass] Looking for DTLS.prx to enable logging...\n");
        find_dtls_prx_module();
    }

    // Enable native DTLS logging
    if (g_dtls_prx_base_address != 0 && !g_dtls_logging_enabled) {
        final_printf("[rust_psn_bypass] Enabling DTLS native logging from Startup hook...\n");
        enable_dtls_native_logging();
    }

    // Call original with isUnencrypted=1 (true)
    final_printf("[rust_psn_bypass] Calling original DTLS.Startup...\n");
    g_dtls_startup_original(thisptr, isServer, serverAddress, serverPort, cipherList, cipherSuites, 1);
    final_printf("[rust_psn_bypass] DTLS.Startup completed\n");
}

// DTLS.get_IsUnencrypted hook - always return true
int hook_dtls_get_isunencrypted(void) {
    static int logged = 0;
    if (!logged) {
        final_printf("[rust_psn_bypass] DTLS.get_IsUnencrypted hooked - returning TRUE\n");
        logged = 1;
    }
    return 1;  // Always unencrypted
}

// =============================================================================
// PSN Room Matchmaking Bypass
// =============================================================================
// Hook all PSN room functions to bypass matchmaking entirely
// These functions call native Prx* functions which won't work without PSN sign-in

typedef void (*room_wrapper_orig_t)(void* thisptr, void* roomData);
static room_wrapper_orig_t g_createroom_wrapper_original = NULL;
static room_wrapper_orig_t g_leaveroom_wrapper_original = NULL;
static room_wrapper_orig_t g_searchrooms_wrapper_original = NULL;
static room_wrapper_orig_t g_joinroom_wrapper_original = NULL;

void hook_createroom_wrapper(void* thisptr, void* roomData) {
    final_printf("[rust_psn_bypass] CreateRoom called - BYPASSING!\n");
    final_printf("[rust_psn_bypass]   thisptr=%p, roomData=%p\n", thisptr, roomData);
    // Don't call original - return immediately
}

void hook_leaveroom_wrapper(void* thisptr, void* roomData) {
    final_printf("[rust_psn_bypass] LeaveRoom called - BYPASSING!\n");
    final_printf("[rust_psn_bypass]   thisptr=%p, roomData=%p\n", thisptr, roomData);
    // Don't call original - return immediately
}

void hook_searchrooms_wrapper(void* thisptr, void* roomData) {
    final_printf("[rust_psn_bypass] SearchRooms called - BYPASSING!\n");
    final_printf("[rust_psn_bypass]   thisptr=%p, roomData=%p\n", thisptr, roomData);
    // Don't call original - return immediately
}

void hook_joinroom_wrapper(void* thisptr, void* roomData) {
    final_printf("[rust_psn_bypass] JoinRoom called - BYPASSING!\n");
    final_printf("[rust_psn_bypass]   thisptr=%p, roomData=%p\n", thisptr, roomData);
    // Don't call original - return immediately
}

// =============================================================================
// PS+ Subscription Check Bypass
// =============================================================================
// Sony.NP.NpUtils.CheckPlus(CheckPlusRequest request, EmptyResponse response) -> int
// This checks if user has PS+ subscription - blocks connect without it
// We bypass by returning success (0) immediately
typedef int (*checkplus_orig_t)(void* request, void* response);
static checkplus_orig_t g_checkplus_original = NULL;

int hook_checkplus(void* request, void* response) {
    final_printf("[rust_psn_bypass] CheckPlus called - BYPASSING PS+ CHECK!\n");
    final_printf("[rust_psn_bypass]   request=%p, response=%p\n", request, response);

    // Fill in response to indicate success
    if (response) {
        // Response structure - assume it's similar to other NP responses
        // offset 0x14 = some flag that may indicate "initialized"
        // Based on decompiled code: if (*(char *)(param_2 + 0x14) == '\0') checks this
        *(char*)((char*)response + 0x14) = 0;  // Keep as 0 to allow flow to continue
    }

    // Return 0 = success (SCE_OK)
    // The caller checks: if ((int)pcStack_c0 == 0) for success path
    return 0;
}

// CheckAvailablity - network availability check
typedef int (*checkavailablity_orig_t)(void* request, void* response);
static checkavailablity_orig_t g_checkavailablity_original = NULL;

int hook_checkavailablity(void* request, void* response) {
    final_printf("[rust_psn_bypass] CheckAvailablity called - BYPASSING NETWORK CHECK!\n");
    final_printf("[rust_psn_bypass]   request=%p, response=%p\n", request, response);

    if (response) {
        *(char*)((char*)response + 0x14) = 0;
    }

    return 0;  // Success
}

// Rustworks.Connect - called when clicking Connect on a server
// This is the function that initiates the /server/{id}/connect API call
typedef void* (*rustworks_connect_orig_t)(void* rustworks, int serverId, void* password);
static rustworks_connect_orig_t g_rustworks_connect_original = NULL;

void* hook_rustworks_connect(void* rustworks, int serverId, void* password) {
    final_printf("[rust_psn_bypass] *** Rustworks.Connect CALLED! ***\n");
    final_printf("[rust_psn_bypass]   rustworks=%p, serverId=%d, password=%p\n", rustworks, serverId, password);

    // Call original - this will make the /server/{id}/connect API call
    if (g_rustworks_connect_original) {
        void* result = g_rustworks_connect_original(rustworks, serverId, password);
        final_printf("[rust_psn_bypass]   Connect result=%p\n", result);
        return result;
    }
    return NULL;
}

// FindJoinGameUI.Connect - called when user clicks Connect button on server
typedef void (*findjoin_connect_orig_t)(void* thisptr, int idx);
static findjoin_connect_orig_t g_findjoin_connect_original = NULL;

void hook_findjoin_connect(void* thisptr, int idx) {
    final_printf("[rust_psn_bypass] *** FindJoinGameUI.Connect CALLED! idx=%d ***\n", idx);

    if (g_findjoin_connect_original) {
        g_findjoin_connect_original(thisptr, idx);
    }
    final_printf("[rust_psn_bypass] FindJoinGameUI.Connect returned\n");
}

// Coroutine_DoServerPreconnection.MoveNext - called during preconnect coroutine
typedef int (*doserver_preconnect_movenext_orig_t)(void* thisptr);
static doserver_preconnect_movenext_orig_t g_doserver_preconnect_movenext_original = NULL;

int hook_doserver_preconnect_movenext(void* thisptr) {
    int state = *(int*)((char*)thisptr + 0x10);
    final_printf("[rust_psn_bypass] DoServerPreconnection.MoveNext state=%d\n", state);

    // Log key fields from the coroutine state
    void* ui_instance = *(void**)((char*)thisptr + 0x20);  // <>4__this
    int server_index = *(int*)((char*)thisptr + 0x28);     // serverIndex
    void* data_coroutine = *(void**)((char*)thisptr + 0x30); // <checkOnlineCoroutine>5__2 (DataCoroutine<bool>)

    final_printf("[rust_psn_bypass]   ui=%p, serverIndex=%d, dataCoroutine=%p\n",
                 ui_instance, server_index, data_coroutine);

    // If we have a DataCoroutine<bool>, check its state
    // DataCoroutine<bool> layout:
    //   offset 0x10 = result (bool)
    //   offset 0x11 = isComplete (bool)
    if (data_coroutine) {
        char dc_result = *(char*)((char*)data_coroutine + 0x10);
        char dc_isComplete = *(char*)((char*)data_coroutine + 0x11);
        final_printf("[rust_psn_bypass]   DataCoroutine: result=%d, isComplete=%d\n",
                     dc_result, dc_isComplete);

        // FIX: Force result=true and isComplete=true to bypass the online check
        // This is needed because our Coroutine_CheckOnline hook doesn't properly set
        // the result that DataCoroutine expects
        if (state == 1 && dc_isComplete) {
            // State 1 is when DoServerPreconnection checks the DataCoroutine result
            // Force the result to true so the check passes
            *(char*)((char*)data_coroutine + 0x10) = 1;  // result = true
            final_printf("[rust_psn_bypass]   PATCHED DataCoroutine result to TRUE\n");
        }
    }

    int result = 0;
    if (g_doserver_preconnect_movenext_original) {
        final_printf("[rust_psn_bypass]   Calling DoServerPreconnection original...\n");
        result = g_doserver_preconnect_movenext_original(thisptr);
        final_printf("[rust_psn_bypass]   DoServerPreconnection original returned!\n");
    }

    int new_state = *(int*)((char*)thisptr + 0x10);
    final_printf("[rust_psn_bypass] DoServerPreconnection.MoveNext returned %d, new_state=%d\n", result, new_state);

    // Extra tracing when coroutine completes
    if (new_state == -1) {
        final_printf("[rust_psn_bypass]   DoServerPreconnection COMPLETED\n");
        // Check if there's server data set at ui_instance + 0x1a0
        if (ui_instance) {
            void* current_server = *(void**)((char*)ui_instance + 0x1a0);
            final_printf("[rust_psn_bypass]   ui->currentServer = %p\n", current_server);
        }
    }

    return result;
}

// ProcessServerPreconnect.MoveNext - trace the actual connect flow
typedef int (*processserverpreconnect_movenext_orig_t)(void* thisptr);
static processserverpreconnect_movenext_orig_t g_processserverpreconnect_movenext_original = NULL;

int hook_processserverpreconnect_movenext(void* thisptr) {
    int state = *(int*)((char*)thisptr + 0x10);
    void* request = *(void**)((char*)thisptr + 0x30);  // IConnectRequest at offset 0x30

    final_printf("[rust_psn_bypass] ProcessServerPreconnect.MoveNext state=%d, request=%p\n", state, request);

    // When entering state 1, the request should be populated
    if (state == 1 && request != NULL) {
        // Try to read the request object fields to see if they're valid
        // IConnectRequest layout from dump.cs:
        // 0x30 = IP string backing field
        // 0x38 = Port int backing field
        // 0x3C = DTLS bool backing field
        final_printf("[rust_psn_bypass]   request class ptr: %p\n", *(void**)request);

        // Try to safely check DTLS field at offset 0x3C
        int dtls = *(int*)((char*)request + 0x3C);
        final_printf("[rust_psn_bypass]   request->DTLS = %d\n", dtls);

        // Check IP at offset 0x30
        void* ip = *(void**)((char*)request + 0x30);
        final_printf("[rust_psn_bypass]   request->IP ptr = %p\n", ip);

        // Check Port at offset 0x38
        int port = *(int*)((char*)request + 0x38);
        final_printf("[rust_psn_bypass]   request->Port = %d\n", port);
    }

    int result = 0;
    if (g_processserverpreconnect_movenext_original) {
        final_printf("[rust_psn_bypass]   Calling original MoveNext...\n");
        result = g_processserverpreconnect_movenext_original(thisptr);
        final_printf("[rust_psn_bypass]   Original returned!\n");
    }

    int new_state = *(int*)((char*)thisptr + 0x10);
    final_printf("[rust_psn_bypass] ProcessServerPreconnect.MoveNext returned %d, new_state=%d\n", result, new_state);

    return result;
}

// ConnectToServer - trace when actual connect is called
typedef void (*connecttoserver_orig_t)(void* ip, int port, void* serverID, void* nextWipe, void* owner);
static connecttoserver_orig_t g_connecttoserver_original = NULL;

void hook_connecttoserver(void* ip, int port, void* serverID, void* nextWipe, void* owner) {
    final_printf("[rust_psn_bypass] *** ConnectToServer CALLED! ***\n");
    final_printf("[rust_psn_bypass]   ip=%p, port=%d, serverID=%p\n", ip, port, serverID);

    // Try to read IP string if it's an IL2CPP string
    if (ip != NULL) {
        // IL2CPP strings have length at offset 0x10 and chars at offset 0x14
        int len = *(int*)((char*)ip + 0x10);
        if (len > 0 && len < 100) {
            uint16_t* chars = (uint16_t*)((char*)ip + 0x14);
            char buf[100];
            int i;
            for (i = 0; i < len && i < 99; i++) {
                buf[i] = (char)chars[i];  // Simple ASCII conversion
            }
            buf[i] = '\0';
            final_printf("[rust_psn_bypass]   IP string: %s\n", buf);
        }
    }

    if (g_connecttoserver_original) {
        final_printf("[rust_psn_bypass]   Calling original ConnectToServer...\n");
        g_connecttoserver_original(ip, port, serverID, nextWipe, owner);
        final_printf("[rust_psn_bypass]   ConnectToServer returned!\n");
    }
}

// GetEngagedUser.MoveNext - force gotEngagedUser after sign-in dialog loop
typedef int (*getengageduser_movenext_orig_t)(void* thisptr);
static getengageduser_movenext_orig_t g_getengageduser_movenext_original = NULL;

int hook_getengageduser_movenext(void* thisptr) {
    static int loop_count = 0;
    int state = *(int*)((char*)thisptr + 0x10);

    // State 11 is right before looping back to state 2 (sign-in retry loop)
    // After one loop, force gotEngagedUser = true to break out
    if (state == 11) {
        loop_count++;
        if (loop_count >= 1) {
            *(char*)((char*)thisptr + 0x38) = 1;  // gotEngagedUser = true
        }
    }

    if (g_getengageduser_movenext_original) {
        return g_getengageduser_movenext_original(thisptr);
    }
    return 0;
}

// =============================================================================
// DTLS.prx Native Logging
// =============================================================================
// Function pointer types for DTLS.prx native functions
typedef void (*dtls_prx_set_logging_enabled_t)(int enabled);
typedef void (*dtls_prx_set_log_level_t)(int level);

static void enable_dtls_native_logging(void) {
    if (g_dtls_prx_base_address == 0) {
        return;
    }

    // Get function pointers - offsets from Ghidra analysis
    dtls_prx_set_logging_enabled_t set_logging_enabled =
        (dtls_prx_set_logging_enabled_t)(g_dtls_prx_base_address + DTLS_PRX_SET_LOGGING_ENABLED_OFFSET);
    dtls_prx_set_log_level_t set_log_level =
        (dtls_prx_set_log_level_t)(g_dtls_prx_base_address + DTLS_PRX_SET_LOG_LEVEL_OFFSET);

    // Enable logging with level 0 (all messages)
    set_log_level(0);
    set_logging_enabled(1);
    g_dtls_logging_enabled = 1;
}

static int find_dtls_prx_module(void) {
    OrbisKernelModule modules[256];
    size_t actual_count = 0;

    if (sceKernelGetModuleList(modules, sizeof(modules), &actual_count) != 0) {
        return -1;
    }

    for (size_t i = 0; i < actual_count; i++) {
        OrbisKernelModuleInfo info;
        info.size = sizeof(info);

        if (sceKernelGetModuleInfo(modules[i], &info) != 0) {
            continue;
        }

        // DTLS.prx is the native DTLS library
        if (strstr(info.name, "DTLS") != NULL || strstr(info.name, "dtls") != NULL) {
            g_dtls_prx_module_handle = modules[i];
            g_dtls_prx_base_address = (uint64_t)info.segmentInfo[0].address;
            final_printf("[rust_psn_bypass] Found DTLS.prx: %s at 0x%lx\n", info.name, g_dtls_prx_base_address);
            return 0;
        }
    }
    return -1;
}

// =============================================================================
// Module loading hook
// =============================================================================
typedef int (*sceKernelLoadStartModule_t)(const char *path, size_t args, const void *argp,
                                           unsigned int flags, void *option, int *result);
static sceKernelLoadStartModule_t g_orig_sceKernelLoadStartModule = NULL;

static void install_il2cpp_hooks(void);
static int find_il2cpp_module(void);
static int install_il2cpp_hook(mh_hook_t *hook, uint64_t rva, void *replacement,
                                void **original_out, const char *name);

int hook_sceKernelLoadStartModule(const char *path, size_t args, const void *argp,
                                   unsigned int flags, void *option, int *result) {
    // Skip loading PS4SharePlayBlocker.prx - it blocks game streaming/remote play features
    if (path && strstr(path, "PS4SharePlayBlocker") != NULL) {
        final_printf("[rust_psn_bypass] SKIPPING module: %s\n", path);
        if (result) *result = 0;
        return 0;  // Return fake success without loading
    }

    int ret = g_orig_sceKernelLoadStartModule(path, args, argp, flags, option, result);

    if (ret >= 0 && path) {
        // Check for Il2CppUserAssemblies
        if (strstr(path, "Il2CppUserAssemblies") != NULL) {
            final_printf("[rust_psn_bypass] Il2CppUserAssemblies loaded (handle=%d)\n", ret);
            if (!g_il2cpp_hooks_installed) {
                g_il2cpp_module_handle = ret;
                if (find_il2cpp_module() == 0) {
                    install_il2cpp_hooks();
                }
            }
        }

        // Check for DTLS.prx - enable native logging
        if (strstr(path, "DTLS") != NULL || strstr(path, "dtls") != NULL) {
            final_printf("[rust_psn_bypass] DTLS.prx loaded (handle=%d): %s\n", ret, path);
            g_dtls_prx_module_handle = ret;
            if (find_dtls_prx_module() == 0) {
                enable_dtls_native_logging();
            }
        }
    }

    return ret;
}

// =============================================================================
// IL2CPP hook installation
// =============================================================================
static int find_il2cpp_module(void) {
    OrbisKernelModule modules[256];
    size_t actual_count = 0;

    if (sceKernelGetModuleList(modules, sizeof(modules), &actual_count) != 0) {
        return -1;
    }

    for (size_t i = 0; i < actual_count; i++) {
        OrbisKernelModuleInfo info;
        info.size = sizeof(info);

        if (sceKernelGetModuleInfo(modules[i], &info) != 0) {
            continue;
        }

        if (strstr(info.name, "Il2CppUserAssemblies") != NULL) {
            g_il2cpp_module_handle = modules[i];
            g_il2cpp_base_address = (uint64_t)info.segmentInfo[0].address;
            final_printf("[rust_psn_bypass] Found Il2CppUserAssemblies at 0x%lx\n", g_il2cpp_base_address);
            return 0;
        }
    }
    return -1;
}

static int install_il2cpp_hook(mh_hook_t *hook, uint64_t rva, void *replacement,
                                void **original_out, const char *name) {
    hook->target_addr = g_il2cpp_base_address + rva;
    hook->user_impl = replacement;
    hook->user_thunk = NULL;
    hook->thunk_slot = NULL;

    if (mh_install(hook) != 0) {
        final_printf("[rust_psn_bypass] FAILED to hook %s\n", name);
        return -1;
    }

    if (original_out) {
        *original_out = hook->orig_fn;
    }

    final_printf("[rust_psn_bypass] Hooked %s\n", name);
    return 0;
}

static void install_il2cpp_hooks(void) {
    if (g_il2cpp_hooks_installed || g_il2cpp_base_address == 0) {
        return;
    }

    final_printf("[rust_psn_bypass] Installing IL2CPP hooks...\n");

    install_il2cpp_hook(&g_hook_display_signin_dialog, IL2CPP_DISPLAY_SIGNIN_DIALOG,
                        (void*)hook_display_signin_dialog, NULL, "DisplaySigninDialog");

    install_il2cpp_hook(&g_hook_check_online_ps4, IL2CPP_CHECK_ONLINE_PS4,
                        (void*)hook_check_online_ps4, NULL, "CheckOnline_PS4");

    install_il2cpp_hook(&g_hook_request_display_signon, IL2CPP_REQUEST_DISPLAY_SIGNON,
                        (void*)hook_request_display_signon,
                        (void**)&g_request_display_signon_original, "RequestDisplaySignOnDialog");

    install_il2cpp_hook(&g_hook_ps4_is_signed_in, IL2CPP_PS4_IS_SIGNED_IN,
                        (void*)hook_ps4_is_signed_in, NULL, "IsSignedIn");

    install_il2cpp_hook(&g_hook_ps4_can_use_online, IL2CPP_PS4_CAN_USE_ONLINE,
                        (void*)hook_ps4_can_use_online, NULL, "CanUseOnline");

    install_il2cpp_hook(&g_hook_ps4_user_has_mp_perm, IL2CPP_PS4_USER_HAS_MP_PERM,
                        (void*)hook_ps4_user_has_mp_perm,
                        (void**)&g_user_has_mp_perm_original, "UserHasMultiplayerPermission");

    install_il2cpp_hook(&g_hook_ps4_get_engaged_user_id, IL2CPP_PS4_GET_ENGAGED_USER_ID,
                        (void*)hook_ps4_get_engaged_user_id, NULL, "GetEngagedUserID");

    install_il2cpp_hook(&g_hook_frontend_is_engaged_signed_in, IL2CPP_FRONTEND_IS_ENGAGED_SIGNED_IN,
                        (void*)hook_frontend_is_engaged_signed_in, NULL, "IsEngagedUserSignedIn");

    install_il2cpp_hook(&g_hook_getengageduser_movenext, IL2CPP_GETENGAGEDUSER_MOVENEXT,
                        (void*)hook_getengageduser_movenext,
                        (void**)&g_getengageduser_movenext_original, "GetEngagedUser.MoveNext");

    install_il2cpp_hook(&g_hook_rustworks_get_root, IL2CPP_RUSTWORKS_GET_ROOT,
                        (void*)hook_rustworks_get_root,
                        (void**)&g_get_root_original, "Rustworks.get_Root");

    install_il2cpp_hook(&g_hook_webrequest_set_url, IL2CPP_WEBREQUEST_INTERNAL_SET_URL,
                        (void*)hook_webrequest_internal_set_url,
                        (void**)&g_internal_set_url_original, "UnityWebRequest.InternalSetUrl");

    install_il2cpp_hook(&g_hook_coroutine_check_online, IL2CPP_COROUTINE_CHECK_ONLINE_MOVENEXT,
                        (void*)hook_coroutine_check_online_movenext,
                        NULL, "Coroutine_CheckOnline.MoveNext");

    install_il2cpp_hook(&g_hook_get_rustworks, IL2CPP_PLATFORMSERVICES_GET_RUSTWORKS,
                        (void*)hook_get_rustworks,
                        (void**)&g_get_rustworks_original, "PlatformServices.get_Rustworks");

    install_il2cpp_hook(&g_hook_rustworks_initialise, IL2CPP_RUSTWORKS_INITIALISE,
                        (void*)hook_rustworks_initialise,
                        (void**)&g_rustworks_initialise_original, "Rustworks.Initialise");

    // Debug logging hooks - capture Unity Debug.Log output for better error visibility
    install_il2cpp_hook(&g_hook_debug_log, IL2CPP_DEBUG_LOG,
                        (void*)hook_debug_log,
                        (void**)&g_debug_log_original, "Debug.Log");

    install_il2cpp_hook(&g_hook_debug_log_error, IL2CPP_DEBUG_LOG_ERROR,
                        (void*)hook_debug_log_error,
                        (void**)&g_debug_log_error_original, "Debug.LogError");

    install_il2cpp_hook(&g_hook_debug_log_warning, IL2CPP_DEBUG_LOG_WARNING,
                        (void*)hook_debug_log_warning,
                        (void**)&g_debug_log_warning_original, "Debug.LogWarning");

    install_il2cpp_hook(&g_hook_debug_log_exception, IL2CPP_DEBUG_LOG_EXCEPTION,
                        (void*)hook_debug_log_exception,
                        (void**)&g_debug_log_exception_original, "Debug.LogException");

    install_il2cpp_hook(&g_hook_debug_is_debug_build, IL2CPP_DEBUG_IS_DEBUG_BUILD,
                        (void*)hook_debug_is_debug_build,
                        (void**)&g_debug_is_debug_build_original, "Debug.isDebugBuild");

    // Web request error logging
    install_il2cpp_hook(&g_hook_webrequest_get_error, IL2CPP_WEBREQUEST_GET_ERROR,
                        (void*)hook_webrequest_get_error,
                        (void**)&g_webrequest_get_error_original, "UnityWebRequest.get_error");

    // Facepunch.Output.LogHandler - captures all Rust game log output
    install_il2cpp_hook(&g_hook_output_loghandler, IL2CPP_OUTPUT_LOGHANDLER,
                        (void*)hook_output_loghandler,
                        (void**)&g_output_loghandler_original, "Output.LogHandler");

    // ConsoleUI.Log - captures console output
    install_il2cpp_hook(&g_hook_consoleui_log, IL2CPP_CONSOLEUI_LOG,
                        (void*)hook_consoleui_log,
                        (void**)&g_consoleui_log_original, "ConsoleUI.Log");

    // DTLS InvalidPacket hooks - debug packet rejection at DTLS layer
    install_il2cpp_hook(&g_hook_dtls_client_invalidpacket, IL2CPP_DTLS_CLIENT_INVALIDPACKET,
                        (void*)hook_dtls_client_invalidpacket,
                        (void**)&g_dtls_client_invalidpacket_original, "DTLS.Client.InvalidPacket");
    install_il2cpp_hook(&g_hook_dtls_server_invalidpacket, IL2CPP_DTLS_SERVER_INVALIDPACKET,
                        (void*)hook_dtls_server_invalidpacket,
                        (void**)&g_dtls_server_invalidpacket_original, "DTLS.Server.InvalidPacket");

    // LiteNetLib InvalidPacket hooks - debug packet rejection at LiteNetLib layer
    install_il2cpp_hook(&g_hook_litenetlib_client_invalidpacket, IL2CPP_LITENETLIB_CLIENT_INVALIDPACKET,
                        (void*)hook_litenetlib_client_invalidpacket,
                        (void**)&g_litenetlib_client_invalidpacket_original, "LiteNetLib.Client.InvalidPacket");
    install_il2cpp_hook(&g_hook_litenetlib_server_invalidpacket, IL2CPP_LITENETLIB_SERVER_INVALIDPACKET,
                        (void*)hook_litenetlib_server_invalidpacket,
                        (void**)&g_litenetlib_server_invalidpacket_original, "LiteNetLib.Server.InvalidPacket");

    // D11.Logger.WriteLog - captures all DTLS logging
    install_il2cpp_hook(&g_hook_logger_writelog, IL2CPP_LOGGER_WRITELOG,
                        (void*)hook_logger_writelog,
                        (void**)&g_logger_writelog_original, "D11.Logger.WriteLog");

    // DTLS SSL handshake callback - monitor handshake state
    install_il2cpp_hook(&g_hook_dtls_ssl_info_callback, DTLS_SSL_INFO_CALLBACK,
                        (void*)hook_dtls_ssl_info_callback,
                        (void**)&g_dtls_ssl_info_callback_original, "DTLS.SSL.InfoCallback");

    // Network message handler hooks - for debugging game protocol
    install_il2cpp_hook(&g_hook_message_process, IL2CPP_MESSAGE_PROCESS,
                        (void*)hook_message_process,
                        (void**)&g_message_process_original, "Network.MessageProcess");
    install_il2cpp_hook(&g_hook_on_request_user_info, IL2CPP_ON_REQUEST_USER_INFO,
                        (void*)hook_on_request_user_info,
                        (void**)&g_on_request_user_info_original, "Network.OnRequestUserInformation");
    install_il2cpp_hook(&g_hook_request_user_info_process, IL2CPP_REQUEST_USER_INFO_PROCESS,
                        (void*)hook_request_user_info_process,
                        (void**)&g_request_user_info_process_original, "Network.RequestUserInformationProcess");
    install_il2cpp_hook(&g_hook_on_approved, IL2CPP_ON_APPROVED,
                        (void*)hook_on_approved,
                        (void**)&g_on_approved_original, "Network.OnApproved");

    // Client update hooks - for debugging message polling
    install_il2cpp_hook(&g_hook_client_cycle, IL2CPP_CLIENT_CYCLE,
                        (void*)hook_client_cycle,
                        (void**)&g_client_cycle_original, "Client.Cycle");
    install_il2cpp_hook(&g_hook_alienclient_start, IL2CPP_ALIENCLIENT_START,
                        (void*)hook_alienclient_start,
                        (void**)&g_alienclient_start_original, "AlienClient.Start");
    install_il2cpp_hook(&g_hook_alienclient_readthread, IL2CPP_ALIENCLIENT_READTHREAD,
                        (void*)hook_alienclient_readthread,
                        (void**)&g_alienclient_readthread_original, "AlienClient.ReadThread");
    install_il2cpp_hook(&g_hook_networkmessages_receive, IL2CPP_NETWORKMESSAGES_RECEIVE,
                        (void*)hook_networkmessages_receive,
                        (void**)&g_networkmessages_receive_original, "NetworkMessages.ReceiveMessage");
    install_il2cpp_hook(&g_hook_dtls_process_recv_buffer, IL2CPP_DTLS_PROCESS_RECV_BUFFER,
                        (void*)hook_dtls_process_recv_buffer,
                        (void**)&g_dtls_process_recv_buffer_original, "DTLSConnection.ProcessRecvBuffer");
    install_il2cpp_hook(&g_hook_client_handle_message, IL2CPP_CLIENT_HANDLE_MESSAGE,
                        (void*)hook_client_handle_message,
                        (void**)&g_client_handle_message_original, "Client.HandleMessage");

    // Rustworks request completion logging - DISABLED: RVA was wrong, pointed to OutlineObject.ShouldDisplay
    // install_il2cpp_hook(&g_hook_rustworks_request_complete, IL2CPP_RUSTWORKS_REQUEST_COMPLETE,
    //                     (void*)hook_rustworks_request_complete,
    //                     (void**)&g_rustworks_request_complete_original, "Rustworks.Request.Complete");

    // Local server mode - force isRunningLocalServer to return true
    install_il2cpp_hook(&g_hook_localserver_get_is_running, IL2CPP_LOCALSERVER_GET_IS_RUNNING,
                        (void*)hook_localserver_get_is_running, NULL, "LocalServer.get_isRunningLocalServer");

    // DTLS encryption bypass - force unencrypted mode for custom server compatibility
    // Hook Startup (called by Facepunch.Network.DTLS.Client.Connect)
    install_il2cpp_hook(&g_hook_dtls_startup, IL2CPP_DTLS_STARTUP,
                        (void*)hook_dtls_startup, (void**)&g_dtls_startup_original, "DTLS.Startup");
    // Also hook get_IsUnencrypted to always return true
    install_il2cpp_hook(&g_hook_dtls_get_isunencrypted, IL2CPP_DTLS_GET_ISUNENCRYPTED,
                        (void*)hook_dtls_get_isunencrypted, NULL, "DTLS.get_IsUnencrypted");

    // PSN Room matchmaking bypass - skip all PSN room calls
    install_il2cpp_hook(&g_hook_createroom_wrapper, IL2CPP_CREATEROOM_WRAPPER,
                        (void*)hook_createroom_wrapper, (void**)&g_createroom_wrapper_original, "CreateRoom");
    install_il2cpp_hook(&g_hook_leaveroom_wrapper, IL2CPP_LEAVEROOM_WRAPPER,
                        (void*)hook_leaveroom_wrapper, (void**)&g_leaveroom_wrapper_original, "LeaveRoom");
    install_il2cpp_hook(&g_hook_searchrooms_wrapper, IL2CPP_SEARCHROOMS_WRAPPER,
                        (void*)hook_searchrooms_wrapper, (void**)&g_searchrooms_wrapper_original, "SearchRooms");
    install_il2cpp_hook(&g_hook_joinroom_wrapper, IL2CPP_JOINROOM_WRAPPER,
                        (void*)hook_joinroom_wrapper, (void**)&g_joinroom_wrapper_original, "JoinRoom");

    // PS+ subscription check bypass - required for connecting without PS+
    install_il2cpp_hook(&g_hook_checkplus, IL2CPP_CHECKPLUS,
                        (void*)hook_checkplus, (void**)&g_checkplus_original, "CheckPlus");

    // Network availability check bypass
    install_il2cpp_hook(&g_hook_checkavailablity, IL2CPP_CHECKAVAILABLITY,
                        (void*)hook_checkavailablity, (void**)&g_checkavailablity_original, "CheckAvailablity");

    // Rustworks.Connect - trace API connect calls when clicking Connect on a server
    install_il2cpp_hook(&g_hook_rustworks_connect, IL2CPP_RUSTWORKS_CONNECT,
                        (void*)hook_rustworks_connect, (void**)&g_rustworks_connect_original, "Rustworks.Connect");

    // UI Connect flow tracing
    install_il2cpp_hook(&g_hook_findjoin_connect, IL2CPP_FINDJOIN_CONNECT,
                        (void*)hook_findjoin_connect, (void**)&g_findjoin_connect_original, "FindJoinGameUI.Connect");
    install_il2cpp_hook(&g_hook_doserver_preconnect_movenext, IL2CPP_DOSERVER_PRECONNECT_MOVENEXT,
                        (void*)hook_doserver_preconnect_movenext, (void**)&g_doserver_preconnect_movenext_original, "DoServerPreconnection.MoveNext");
    install_il2cpp_hook(&g_hook_processserverpreconnect_movenext, IL2CPP_PROCESSSERVERPRECONNECT_MOVENEXT,
                        (void*)hook_processserverpreconnect_movenext, (void**)&g_processserverpreconnect_movenext_original, "ProcessServerPreconnect.MoveNext");
    install_il2cpp_hook(&g_hook_connecttoserver, IL2CPP_CONNECTTOSERVER,
                        (void*)hook_connecttoserver, (void**)&g_connecttoserver_original, "ConnectToServer");

    g_il2cpp_hooks_installed = 1;
    final_printf("[rust_psn_bypass] IL2CPP hooks installed\n");
}

// =============================================================================
// Helper to install eboot hook
// =============================================================================
static int install_eboot_hook(mh_hook_t *hook, uint64_t offset, void *replacement, const char *name) {
    hook->target_addr = g_base_address + offset;
    hook->user_impl = replacement;
    hook->user_thunk = NULL;
    hook->thunk_slot = NULL;

    if (mh_install(hook) != 0) {
        final_printf("[rust_psn_bypass] FAILED to hook %s\n", name);
        return -1;
    }

    final_printf("[rust_psn_bypass] Hooked %s\n", name);
    return 0;
}

// =============================================================================
// Plugin entry points
// =============================================================================
s32 attr_public plugin_load(s32 argc, const char* argv[]) {
    final_printf("[rust_psn_bypass] Loading plugin v0x%08x\n", g_pluginVersion);

    struct proc_info proc_info;
    if (sys_sdk_proc_info(&proc_info) != 0) {
        final_printf("[rust_psn_bypass] Failed to get process info\n");
        return -1;
    }

    // Check if this is Rust Console Edition
    final_printf("[rust_psn_bypass] titleid: %s\n", proc_info.titleid);
    final_printf("[rust_psn_bypass] contentid: %s\n", proc_info.contentid);
    final_printf("[rust_psn_bypass] version: %s\n", proc_info.version);

    if (strncmp(proc_info.titleid, "CUSA14296", 9) != 0) {
        final_printf("[rust_psn_bypass] Wrong title ID (%s), not loading plugin\n", proc_info.titleid);
        final_printf("[rust_psn_bypass] This plugin is for Rust Console Edition only (CUSA14296)\n");
        send_notification("Rust CE Patch by earthonion\nWrong game! CUSA14296 only");
        return -1;
    }

    if (strncmp(proc_info.version, "01.20", 5) != 0) {
        final_printf("[rust_psn_bypass] Wrong version (%s), not loading plugin\n", proc_info.version);
        final_printf("[rust_psn_bypass] This plugin is for version 01.20 only\n");
        char msg[128];
        snprintf(msg, sizeof(msg), "Rust CE Patch by earthonion\nWrong version! v01.20 only\nYours: %s", proc_info.version);
        send_notification(msg);
        return -1;
    }

    g_base_address = proc_info.base_address;
    final_printf("[rust_psn_bypass] Base: 0x%lx, PID: %d\n", g_base_address, proc_info.pid);

    // Install eboot hooks for sceNp* functions
    install_eboot_hook(&g_hook_sceNpGetAccountIdA, OFFSET_sceNpGetAccountIdA,
                       (void*)hook_sceNpGetAccountIdA, "sceNpGetAccountIdA");
    install_eboot_hook(&g_hook_sceNpWebApiInitialize, OFFSET_sceNpWebApiInitialize,
                       (void*)hook_sceNpWebApiInitialize, "sceNpWebApiInitialize");
    install_eboot_hook(&g_hook_sceNpWebApiCreateContextA, OFFSET_sceNpWebApiCreateContextA,
                       (void*)hook_sceNpWebApiCreateContextA, "sceNpWebApiCreateContextA");
    install_eboot_hook(&g_hook_sceNpWebApiCreateRequest, OFFSET_sceNpWebApiCreateRequest,
                       (void*)hook_sceNpWebApiCreateRequest, "sceNpWebApiCreateRequest");
    install_eboot_hook(&g_hook_sceNpWebApiSendRequest2, OFFSET_sceNpWebApiSendRequest2,
                       (void*)hook_sceNpWebApiSendRequest2, "sceNpWebApiSendRequest2");
    install_eboot_hook(&g_hook_sceNpWebApiReadData, OFFSET_sceNpWebApiReadData,
                       (void*)hook_sceNpWebApiReadData, "sceNpWebApiReadData");
    install_eboot_hook(&g_hook_sceNpWebApiDeleteRequest, OFFSET_sceNpWebApiDeleteRequest,
                       (void*)hook_sceNpWebApiDeleteRequest, "sceNpWebApiDeleteRequest");

    // Hook sceKernelLoadStartModule to catch IL2CPP loading
    g_hook_sceKernelLoadStartModule.target_addr = g_base_address + OFFSET_sceKernelLoadStartModule;
    g_hook_sceKernelLoadStartModule.user_impl = (void*)hook_sceKernelLoadStartModule;
    g_hook_sceKernelLoadStartModule.user_thunk = NULL;
    g_hook_sceKernelLoadStartModule.thunk_slot = NULL;

    if (mh_install(&g_hook_sceKernelLoadStartModule) == 0) {
        g_orig_sceKernelLoadStartModule = (sceKernelLoadStartModule_t)g_hook_sceKernelLoadStartModule.orig_fn;
        final_printf("[rust_psn_bypass] Hooked sceKernelLoadStartModule\n");
    }

    // Check if IL2CPP is already loaded
    if (find_il2cpp_module() == 0) {
        install_il2cpp_hooks();
    }

    // Check if DTLS.prx is already loaded
    final_printf("[rust_psn_bypass] Checking if DTLS.prx is already loaded...\n");
    if (find_dtls_prx_module() == 0) {
        final_printf("[rust_psn_bypass] DTLS.prx found, calling enable_dtls_native_logging()\n");
        enable_dtls_native_logging();
        final_printf("[rust_psn_bypass] enable_dtls_native_logging() returned\n");
    } else {
        final_printf("[rust_psn_bypass] DTLS.prx not loaded yet\n");
    }

    final_printf("[rust_psn_bypass] Plugin loaded successfully\n");
    send_notification("Rust CE Patch by earthonion\nLoaded successfully!\nCUSA14296 v01.20");
    return 0;
}

s32 attr_public plugin_unload(s32 argc, const char* argv[]) {
    final_printf("[rust_psn_bypass] Unloading plugin\n");

    // Remove eboot hooks
    if (g_hook_sceNpGetAccountIdA.installed) mh_remove(&g_hook_sceNpGetAccountIdA);
    if (g_hook_sceNpWebApiInitialize.installed) mh_remove(&g_hook_sceNpWebApiInitialize);
    if (g_hook_sceNpWebApiCreateContextA.installed) mh_remove(&g_hook_sceNpWebApiCreateContextA);
    if (g_hook_sceNpWebApiCreateRequest.installed) mh_remove(&g_hook_sceNpWebApiCreateRequest);
    if (g_hook_sceNpWebApiSendRequest2.installed) mh_remove(&g_hook_sceNpWebApiSendRequest2);
    if (g_hook_sceNpWebApiReadData.installed) mh_remove(&g_hook_sceNpWebApiReadData);
    if (g_hook_sceNpWebApiDeleteRequest.installed) mh_remove(&g_hook_sceNpWebApiDeleteRequest);
    if (g_hook_sceKernelLoadStartModule.installed) mh_remove(&g_hook_sceKernelLoadStartModule);

    // Remove IL2CPP hooks
    if (g_hook_rustworks_get_root.installed) mh_remove(&g_hook_rustworks_get_root);
    if (g_hook_display_signin_dialog.installed) mh_remove(&g_hook_display_signin_dialog);
    if (g_hook_check_online_ps4.installed) mh_remove(&g_hook_check_online_ps4);
    if (g_hook_request_display_signon.installed) mh_remove(&g_hook_request_display_signon);
    if (g_hook_ps4_is_signed_in.installed) mh_remove(&g_hook_ps4_is_signed_in);
    if (g_hook_ps4_can_use_online.installed) mh_remove(&g_hook_ps4_can_use_online);
    if (g_hook_ps4_user_has_mp_perm.installed) mh_remove(&g_hook_ps4_user_has_mp_perm);
    if (g_hook_ps4_get_engaged_user_id.installed) mh_remove(&g_hook_ps4_get_engaged_user_id);
    if (g_hook_frontend_is_engaged_signed_in.installed) mh_remove(&g_hook_frontend_is_engaged_signed_in);
    if (g_hook_getengageduser_movenext.installed) mh_remove(&g_hook_getengageduser_movenext);
    if (g_hook_webrequest_set_url.installed) mh_remove(&g_hook_webrequest_set_url);
    if (g_hook_coroutine_check_online.installed) mh_remove(&g_hook_coroutine_check_online);
    if (g_hook_get_rustworks.installed) mh_remove(&g_hook_get_rustworks);
    if (g_hook_rustworks_initialise.installed) mh_remove(&g_hook_rustworks_initialise);
    if (g_hook_debug_log.installed) mh_remove(&g_hook_debug_log);
    if (g_hook_debug_log_error.installed) mh_remove(&g_hook_debug_log_error);
    if (g_hook_debug_log_warning.installed) mh_remove(&g_hook_debug_log_warning);
    if (g_hook_debug_log_exception.installed) mh_remove(&g_hook_debug_log_exception);
    if (g_hook_debug_is_debug_build.installed) mh_remove(&g_hook_debug_is_debug_build);
    if (g_hook_webrequest_get_error.installed) mh_remove(&g_hook_webrequest_get_error);
    if (g_hook_rustworks_request_complete.installed) mh_remove(&g_hook_rustworks_request_complete);
    if (g_hook_localserver_get_is_running.installed) mh_remove(&g_hook_localserver_get_is_running);
    if (g_hook_dtls_startup.installed) mh_remove(&g_hook_dtls_startup);
    if (g_hook_dtls_get_isunencrypted.installed) mh_remove(&g_hook_dtls_get_isunencrypted);
    if (g_hook_createroom_wrapper.installed) mh_remove(&g_hook_createroom_wrapper);
    if (g_hook_leaveroom_wrapper.installed) mh_remove(&g_hook_leaveroom_wrapper);
    if (g_hook_searchrooms_wrapper.installed) mh_remove(&g_hook_searchrooms_wrapper);
    if (g_hook_joinroom_wrapper.installed) mh_remove(&g_hook_joinroom_wrapper);
    if (g_hook_checkplus.installed) mh_remove(&g_hook_checkplus);
    if (g_hook_checkavailablity.installed) mh_remove(&g_hook_checkavailablity);
    if (g_hook_rustworks_connect.installed) mh_remove(&g_hook_rustworks_connect);
    if (g_hook_findjoin_connect.installed) mh_remove(&g_hook_findjoin_connect);
    if (g_hook_doserver_preconnect_movenext.installed) mh_remove(&g_hook_doserver_preconnect_movenext);
    if (g_hook_processserverpreconnect_movenext.installed) mh_remove(&g_hook_processserverpreconnect_movenext);
    if (g_hook_connecttoserver.installed) mh_remove(&g_hook_connecttoserver);

    final_printf("[rust_psn_bypass] Plugin unloaded\n");
    return 0;
}

s32 attr_module_hidden module_start(s64 argc, const void *args) {
    return 0;
}

s32 attr_module_hidden module_stop(s64 argc, const void *args) {
    return 0;
}
