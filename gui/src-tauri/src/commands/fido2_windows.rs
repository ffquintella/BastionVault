//! Windows-native FIDO2/WebAuthn ceremonies via `webauthn.dll`.
//!
//! Since Windows 10 1903 the OS claims exclusive access to FIDO/CTAP2 USB
//! HID interfaces on behalf of its own WebAuthn stack. A process that opens
//! those interfaces directly — which is what the Mozilla `authenticator`
//! crate's Windows transport does — cannot enumerate a security key at all,
//! so the ceremony never leaves the "waiting for a device" state. The only
//! supported way for a Windows application to run a WebAuthn ceremony is to
//! call the platform API in `webauthn.dll`, which owns the device and drives
//! its own presence/PIN UI.
//!
//! `webauthn.dll` is resolved at run time rather than linked, so a Windows
//! build still starts on an installation that does not ship it (pre-1809);
//! the ceremony then fails with an explicit error instead of the process
//! failing to load.
//!
//! The bindings below are hand-written because `windows-rs` carries no
//! WebAuthn metadata — `webauthn.h` is not part of the win32metadata
//! projection. Struct layouts mirror the Windows SDK header exactly and are
//! declared only as far as the struct version this module requests.

use std::ffi::c_void;
use std::sync::OnceLock;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::error::CommandError;

use super::fido2_native::{
    AssertCeremonyArgs, AssertCeremonyOutput, RegisterCeremonyArgs, RegisterCeremonyOutput,
};

// ── Constants from webauthn.h ────────────────────────────────────────

const RP_ENTITY_INFORMATION_VERSION_1: u32 = 1;
const USER_ENTITY_INFORMATION_VERSION_1: u32 = 1;
const CLIENT_DATA_VERSION_1: u32 = 1;
const COSE_CREDENTIAL_PARAMETER_VERSION_1: u32 = 1;
const CREDENTIAL_EX_VERSION_1: u32 = 1;

/// `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3` and
/// `..._GET_ASSERTION_OPTIONS_VERSION_4` are both part of the baseline
/// `WEBAUTHN_API_VERSION_1` surface (Windows 10 1809), so requesting them
/// needs no API-version probe. They are the first versions carrying the
/// `pExcludeCredentialList` / `pAllowCredentialList` fields, which let us
/// pin each descriptor to the USB transport.
const MAKE_CREDENTIAL_OPTIONS_VERSION_3: u32 = 3;
const GET_ASSERTION_OPTIONS_VERSION_4: u32 = 4;

/// Roaming (USB/NFC) authenticators only — never the platform authenticator.
/// Matches the USB-only behaviour of the non-Windows CTAP2 path, and keeps a
/// registration from silently binding to Windows Hello on one machine.
const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM: u32 = 2;

const UV_REQUIREMENT_REQUIRED: u32 = 1;
const UV_REQUIREMENT_PREFERRED: u32 = 2;
const UV_REQUIREMENT_DISCOURAGED: u32 = 3;

const ATTESTATION_PREFERENCE_ANY: u32 = 0;
const ATTESTATION_PREFERENCE_NONE: u32 = 1;
const ATTESTATION_PREFERENCE_INDIRECT: u32 = 2;
const ATTESTATION_PREFERENCE_DIRECT: u32 = 3;

const CTAP_TRANSPORT_USB: u32 = 1;

/// `WEBAUTHN_MAX_USER_ID_LENGTH`.
const MAX_USER_ID_LENGTH: usize = 64;

const S_OK: i32 = 0;
const NTE_EXISTS: i32 = 0x8009_000F_u32 as i32;
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;
const NTE_DEVICE_NOT_FOUND: i32 = 0x8009_0035_u32 as i32;
const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;
const HRESULT_ERROR_CANCELLED: i32 = 0x8007_04C7_u32 as i32;
const HRESULT_ERROR_TIMEOUT: i32 = 0x8007_05B4_u32 as i32;

// ── Struct layouts (mirror webauthn.h) ──────────────────────────────

#[repr(C)]
struct RpEntityInformation {
    dw_version: u32,
    pwsz_id: *const u16,
    pwsz_name: *const u16,
    pwsz_icon: *const u16,
}

#[repr(C)]
struct UserEntityInformation {
    dw_version: u32,
    cb_id: u32,
    pb_id: *const u8,
    pwsz_name: *const u16,
    pwsz_icon: *const u16,
    pwsz_display_name: *const u16,
}

#[repr(C)]
struct ClientData {
    dw_version: u32,
    cb_client_data_json: u32,
    pb_client_data_json: *const u8,
    pwsz_hash_alg_id: *const u16,
}

#[repr(C)]
struct CoseCredentialParameter {
    dw_version: u32,
    pwsz_credential_type: *const u16,
    l_alg: i32,
}

#[repr(C)]
struct CoseCredentialParameters {
    c_credential_parameters: u32,
    p_credential_parameters: *const CoseCredentialParameter,
}

#[repr(C)]
struct Credential {
    dw_version: u32,
    cb_id: u32,
    pb_id: *const u8,
    pwsz_credential_type: *const u16,
}

#[repr(C)]
struct Credentials {
    c_credentials: u32,
    p_credentials: *const Credential,
}

#[repr(C)]
struct CredentialEx {
    dw_version: u32,
    cb_id: u32,
    pb_id: *const u8,
    pwsz_credential_type: *const u16,
    dw_transports: u32,
}

#[repr(C)]
struct CredentialList {
    c_credentials: u32,
    pp_credentials: *const *const CredentialEx,
}

#[repr(C)]
struct Extensions {
    c_extensions: u32,
    p_extensions: *const c_void,
}

/// Declared through `VERSION_3`; later fields are never read by a
/// `dwVersion = 3` call.
#[repr(C)]
struct MakeCredentialOptions {
    dw_version: u32,
    dw_timeout_milliseconds: u32,
    credential_list: Credentials,
    extensions: Extensions,
    dw_authenticator_attachment: u32,
    b_require_resident_key: i32,
    dw_user_verification_requirement: u32,
    dw_attestation_conveyance_preference: u32,
    dw_flags: u32,
    p_cancellation_id: *const c_void,
    p_exclude_credential_list: *const CredentialList,
}

/// Declared through `VERSION_4`; later fields are never read by a
/// `dwVersion = 4` call.
#[repr(C)]
struct GetAssertionOptions {
    dw_version: u32,
    dw_timeout_milliseconds: u32,
    credential_list: Credentials,
    extensions: Extensions,
    dw_authenticator_attachment: u32,
    dw_user_verification_requirement: u32,
    dw_flags: u32,
    pwsz_u2f_app_id: *const u16,
    pb_u2f_app_id: *const i32,
    p_cancellation_id: *const c_void,
    p_allow_credential_list: *const CredentialList,
}

/// Declared through `VERSION_1`. Windows allocates the current version, so
/// reading this prefix of a larger allocation is sound; the fields this
/// module needs (`pbAttestationObject`, `pbCredentialId`) are all V1.
#[repr(C)]
struct CredentialAttestation {
    dw_version: u32,
    pwsz_format_type: *const u16,
    cb_authenticator_data: u32,
    pb_authenticator_data: *const u8,
    cb_attestation: u32,
    pb_attestation: *const u8,
    dw_attestation_decode_type: u32,
    pv_attestation_decode: *const c_void,
    cb_attestation_object: u32,
    pb_attestation_object: *const u8,
    cb_credential_id: u32,
    pb_credential_id: *const u8,
}

/// Declared through `VERSION_1`, same reasoning as [`CredentialAttestation`].
#[repr(C)]
struct Assertion {
    dw_version: u32,
    cb_authenticator_data: u32,
    pb_authenticator_data: *const u8,
    cb_signature: u32,
    pb_signature: *const u8,
    credential: Credential,
    cb_user_id: u32,
    pb_user_id: *const u8,
}

// ── Dynamically resolved entry points ───────────────────────────────

type FnMakeCredential = unsafe extern "system" fn(
    *mut c_void,
    *const RpEntityInformation,
    *const UserEntityInformation,
    *const CoseCredentialParameters,
    *const ClientData,
    *const MakeCredentialOptions,
    *mut *mut CredentialAttestation,
) -> i32;

type FnGetAssertion = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    *const ClientData,
    *const GetAssertionOptions,
    *mut *mut Assertion,
) -> i32;

type FnFreeCredentialAttestation = unsafe extern "system" fn(*mut CredentialAttestation);
type FnFreeAssertion = unsafe extern "system" fn(*mut Assertion);
type FnGetErrorName = unsafe extern "system" fn(i32) -> *const u16;

/// The untyped shape `GetProcAddress` hands back (`FARPROC`'s payload).
type RawProc = unsafe extern "system" fn() -> isize;

struct WebAuthnApi {
    make_credential: FnMakeCredential,
    get_assertion: FnGetAssertion,
    free_credential_attestation: FnFreeCredentialAttestation,
    free_assertion: FnFreeAssertion,
    get_error_name: Option<FnGetErrorName>,
}

/// `None` once resolution has been attempted and failed. The module handle
/// is deliberately never freed: the entry points stay valid for the life of
/// the process, which is exactly the lifetime of the cached pointers.
static API: OnceLock<Option<WebAuthnApi>> = OnceLock::new();

fn resolve_proc(module: HMODULE, name: &str) -> Option<RawProc> {
    let mut symbol: Vec<u8> = name.as_bytes().to_vec();
    symbol.push(0);
    // SAFETY: `symbol` is NUL-terminated and outlives the call.
    unsafe { GetProcAddress(module, PCSTR(symbol.as_ptr())) }
}

fn load_api() -> Option<WebAuthnApi> {
    let dll = to_wide("webauthn.dll");
    // SAFETY: `dll` is a NUL-terminated wide string that outlives the call.
    let module = match unsafe { LoadLibraryW(PCWSTR(dll.as_ptr())) } {
        Ok(m) => m,
        Err(e) => {
            log::warn!("FIDO2: webauthn.dll could not be loaded: {e}");
            return None;
        }
    };

    let make_credential = resolve_proc(module, "WebAuthNAuthenticatorMakeCredential")?;
    let get_assertion = resolve_proc(module, "WebAuthNAuthenticatorGetAssertion")?;
    let free_credential_attestation = resolve_proc(module, "WebAuthNFreeCredentialAttestation")?;
    let free_assertion = resolve_proc(module, "WebAuthNFreeAssertion")?;
    let get_error_name = resolve_proc(module, "WebAuthNGetErrorName");

    // SAFETY: each symbol is transmuted to the signature `webauthn.h`
    // declares for it. A mismatch here would be a transcription error in the
    // types above, not a run-time condition.
    unsafe {
        Some(WebAuthnApi {
            make_credential: std::mem::transmute::<RawProc, FnMakeCredential>(make_credential),
            get_assertion: std::mem::transmute::<RawProc, FnGetAssertion>(get_assertion),
            free_credential_attestation: std::mem::transmute::<
                RawProc,
                FnFreeCredentialAttestation,
            >(free_credential_attestation),
            free_assertion: std::mem::transmute::<RawProc, FnFreeAssertion>(free_assertion),
            get_error_name: get_error_name
                .map(|f| std::mem::transmute::<RawProc, FnGetErrorName>(f)),
        })
    }
}

fn api() -> Result<&'static WebAuthnApi, CommandError> {
    API.get_or_init(load_api).as_ref().ok_or_else(|| {
        CommandError::from(
            "Security keys need the Windows WebAuthn platform API (webauthn.dll), which this \
             installation of Windows does not provide. Windows 10 1809 or newer is required.",
        )
    })
}

// ── Helpers ─────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a NUL-terminated wide string returned by `webauthn.dll`.
///
/// # Safety
/// `ptr` must be NUL-terminated or null.
unsafe fn from_wide(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(slice))
}

/// Copy an out-parameter byte buffer owned by `webauthn.dll`.
///
/// # Safety
/// `ptr` must be valid for `len` bytes, or null when `len` is 0.
unsafe fn copy_bytes(ptr: *const u8, len: u32) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec()
}

pub(crate) fn user_verification_requirement(s: &str) -> u32 {
    match s {
        "required" => UV_REQUIREMENT_REQUIRED,
        "discouraged" => UV_REQUIREMENT_DISCOURAGED,
        _ => UV_REQUIREMENT_PREFERRED,
    }
}

pub(crate) fn attestation_preference(s: &str) -> u32 {
    match s {
        "none" => ATTESTATION_PREFERENCE_NONE,
        "indirect" => ATTESTATION_PREFERENCE_INDIRECT,
        "direct" | "enterprise" => ATTESTATION_PREFERENCE_DIRECT,
        _ => ATTESTATION_PREFERENCE_ANY,
    }
}

/// `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3` carries only
/// the boolean `bRequireResidentKey`; `bPreferResidentKey` arrived in
/// `VERSION_4`. "preferred" therefore maps to a non-discoverable credential,
/// which is what this deployment uses anyway — every login supplies a
/// username first, so the credential is always found through
/// `allowCredentials`.
pub(crate) fn require_resident_key(s: &str) -> i32 {
    i32::from(s == "required")
}

fn hresult_message(api: &WebAuthnApi, hr: i32, ceremony: &str) -> CommandError {
    let name = api
        .get_error_name
        // SAFETY: the DLL returns a static NUL-terminated wide string.
        .and_then(|f| unsafe { from_wide(f(hr)) })
        .unwrap_or_else(|| "UnknownError".to_string());

    let detail = format!("{name} (0x{:08X})", hr as u32);
    let message = match hr {
        NTE_EXISTS => "This security key is already registered".to_string(),
        NTE_DEVICE_NOT_FOUND | NTE_NOT_FOUND => {
            "No security key detected. Please insert your key and try again.".to_string()
        }
        NTE_USER_CANCELLED | HRESULT_ERROR_CANCELLED => "Operation was cancelled".to_string(),
        HRESULT_ERROR_TIMEOUT => {
            format!("{ceremony} timed out waiting for your security key")
        }
        _ => format!("Security key error: {detail}"),
    };
    log::warn!("FIDO2 {ceremony} failed via webauthn.dll: {detail}");
    CommandError::from(message)
}

/// Build the `WEBAUTHN_CREDENTIAL_EX` array and the array of pointers into
/// it that `WEBAUTHN_CREDENTIAL_LIST` expects.
///
/// Both are returned because the pointer array borrows the entry array:
/// callers must bind the entries to a live name (`_entries`, not `_`) for
/// the whole FFI call, or the pointers dangle.
fn credential_list(
    ids: &[Vec<u8>],
    credential_type: &[u16],
) -> (Vec<CredentialEx>, Vec<*const CredentialEx>) {
    let entries: Vec<CredentialEx> = ids
        .iter()
        .map(|id| CredentialEx {
            dw_version: CREDENTIAL_EX_VERSION_1,
            cb_id: id.len() as u32,
            pb_id: id.as_ptr(),
            pwsz_credential_type: credential_type.as_ptr(),
            dw_transports: CTAP_TRANSPORT_USB,
        })
        .collect();
    // Second pass: `entries` is fully built, so element addresses are stable.
    let pointers: Vec<*const CredentialEx> = entries.iter().map(|c| c as *const _).collect();
    (entries, pointers)
}

fn empty_credentials() -> Credentials {
    Credentials {
        c_credentials: 0,
        p_credentials: std::ptr::null(),
    }
}

fn empty_extensions() -> Extensions {
    Extensions {
        c_extensions: 0,
        p_extensions: std::ptr::null(),
    }
}

/// Windows treats the timeout as guidance and clamps it itself; the cast
/// just keeps an absurd server-supplied value from wrapping.
fn timeout_ms(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

// ── Ceremonies ──────────────────────────────────────────────────────

/// Run `WebAuthNAuthenticatorMakeCredential` against the operator's
/// security key.
///
/// `hwnd` is the raw handle of the window the OS dialog is parented to.
/// Blocks until the operator completes or dismisses that dialog, so it must
/// be called from a blocking context, never the UI thread.
pub(crate) fn make_credential(
    hwnd: isize,
    args: &RegisterCeremonyArgs,
) -> Result<RegisterCeremonyOutput, CommandError> {
    let api = api()?;

    if args.user_id.is_empty() {
        return Err("FIDO2 registration: server returned an empty user handle".into());
    }
    if args.user_id.len() > MAX_USER_ID_LENGTH {
        return Err(format!(
            "FIDO2 registration: user handle is {} bytes, Windows allows at most {}",
            args.user_id.len(),
            MAX_USER_ID_LENGTH
        )
        .into());
    }
    if args.cose_algorithms.is_empty() {
        return Err("FIDO2 registration: server offered no credential algorithms".into());
    }

    let rp_id = to_wide(&args.rp_id);
    let rp_name = to_wide(&args.rp_name);
    let user_name = to_wide(&args.user_name);
    let user_display_name = to_wide(&args.user_display_name);
    let hash_alg = to_wide("SHA-256");
    let credential_type = to_wide("public-key");

    let rp = RpEntityInformation {
        dw_version: RP_ENTITY_INFORMATION_VERSION_1,
        pwsz_id: rp_id.as_ptr(),
        pwsz_name: rp_name.as_ptr(),
        pwsz_icon: std::ptr::null(),
    };

    let user = UserEntityInformation {
        dw_version: USER_ENTITY_INFORMATION_VERSION_1,
        cb_id: args.user_id.len() as u32,
        pb_id: args.user_id.as_ptr(),
        pwsz_name: user_name.as_ptr(),
        pwsz_icon: std::ptr::null(),
        pwsz_display_name: user_display_name.as_ptr(),
    };

    let cose_params: Vec<CoseCredentialParameter> = args
        .cose_algorithms
        .iter()
        .map(|alg| CoseCredentialParameter {
            dw_version: COSE_CREDENTIAL_PARAMETER_VERSION_1,
            pwsz_credential_type: credential_type.as_ptr(),
            l_alg: i32::try_from(*alg).unwrap_or(-7),
        })
        .collect();
    let pub_key_cred_params = CoseCredentialParameters {
        c_credential_parameters: cose_params.len() as u32,
        p_credential_parameters: cose_params.as_ptr(),
    };

    let client_data = ClientData {
        dw_version: CLIENT_DATA_VERSION_1,
        cb_client_data_json: args.client_data_json.len() as u32,
        pb_client_data_json: args.client_data_json.as_ptr(),
        pwsz_hash_alg_id: hash_alg.as_ptr(),
    };

    let (_exclude_entries, exclude_pointers) =
        credential_list(&args.exclude_credential_ids, &credential_type);
    let exclude_list = CredentialList {
        c_credentials: exclude_pointers.len() as u32,
        pp_credentials: exclude_pointers.as_ptr(),
    };

    let options = MakeCredentialOptions {
        dw_version: MAKE_CREDENTIAL_OPTIONS_VERSION_3,
        dw_timeout_milliseconds: timeout_ms(args.timeout_ms),
        credential_list: empty_credentials(),
        extensions: empty_extensions(),
        dw_authenticator_attachment: AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        b_require_resident_key: require_resident_key(&args.resident_key),
        dw_user_verification_requirement: user_verification_requirement(&args.user_verification),
        dw_attestation_conveyance_preference: attestation_preference(&args.attestation),
        dw_flags: 0,
        p_cancellation_id: std::ptr::null(),
        p_exclude_credential_list: if exclude_pointers.is_empty() {
            std::ptr::null()
        } else {
            &exclude_list
        },
    };

    let mut attestation: *mut CredentialAttestation = std::ptr::null_mut();
    // SAFETY: every pointer in the structs above borrows a local buffer that
    // outlives this call, and `attestation` is an out-parameter the DLL
    // fills with an allocation we free below.
    let hr = unsafe {
        (api.make_credential)(
            hwnd as *mut c_void,
            &rp,
            &user,
            &pub_key_cred_params,
            &client_data,
            &options,
            &mut attestation,
        )
    };

    if hr != S_OK {
        if !attestation.is_null() {
            // SAFETY: non-null out-parameter allocated by the DLL.
            unsafe { (api.free_credential_attestation)(attestation) };
        }
        return Err(hresult_message(api, hr, "Registration"));
    }
    if attestation.is_null() {
        return Err("Windows WebAuthn returned no attestation".into());
    }

    // SAFETY: `attestation` is a live allocation from the DLL, whose layout
    // matches `CredentialAttestation` for the V1 prefix read here.
    let output = unsafe {
        let att = &*attestation;
        RegisterCeremonyOutput {
            credential_id: copy_bytes(att.pb_credential_id, att.cb_credential_id),
            attestation_object: copy_bytes(att.pb_attestation_object, att.cb_attestation_object),
        }
    };
    // SAFETY: the buffers were copied above; the allocation is now ours to free.
    unsafe { (api.free_credential_attestation)(attestation) };

    if output.attestation_object.is_empty() {
        return Err("Windows WebAuthn returned an empty attestation object".into());
    }
    Ok(output)
}

/// Run `WebAuthNAuthenticatorGetAssertion` against the operator's security
/// key. Blocking, for the same reason as [`make_credential`].
pub(crate) fn get_assertion(
    hwnd: isize,
    args: &AssertCeremonyArgs,
) -> Result<AssertCeremonyOutput, CommandError> {
    let api = api()?;

    let rp_id = to_wide(&args.rp_id);
    let hash_alg = to_wide("SHA-256");
    let credential_type = to_wide("public-key");

    let client_data = ClientData {
        dw_version: CLIENT_DATA_VERSION_1,
        cb_client_data_json: args.client_data_json.len() as u32,
        pb_client_data_json: args.client_data_json.as_ptr(),
        pwsz_hash_alg_id: hash_alg.as_ptr(),
    };

    let (_allow_entries, allow_pointers) =
        credential_list(&args.allow_credential_ids, &credential_type);
    let allow_list = CredentialList {
        c_credentials: allow_pointers.len() as u32,
        pp_credentials: allow_pointers.as_ptr(),
    };

    let options = GetAssertionOptions {
        dw_version: GET_ASSERTION_OPTIONS_VERSION_4,
        dw_timeout_milliseconds: timeout_ms(args.timeout_ms),
        credential_list: empty_credentials(),
        extensions: empty_extensions(),
        dw_authenticator_attachment: AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        dw_user_verification_requirement: user_verification_requirement(&args.user_verification),
        dw_flags: 0,
        pwsz_u2f_app_id: std::ptr::null(),
        pb_u2f_app_id: std::ptr::null(),
        p_cancellation_id: std::ptr::null(),
        p_allow_credential_list: if allow_pointers.is_empty() {
            std::ptr::null()
        } else {
            &allow_list
        },
    };

    let mut assertion: *mut Assertion = std::ptr::null_mut();
    // SAFETY: as in `make_credential` — borrowed buffers outlive the call and
    // `assertion` is a DLL-owned out-parameter freed below.
    let hr = unsafe {
        (api.get_assertion)(
            hwnd as *mut c_void,
            rp_id.as_ptr(),
            &client_data,
            &options,
            &mut assertion,
        )
    };

    if hr != S_OK {
        if !assertion.is_null() {
            // SAFETY: non-null out-parameter allocated by the DLL.
            unsafe { (api.free_assertion)(assertion) };
        }
        return Err(hresult_message(api, hr, "Authentication"));
    }
    if assertion.is_null() {
        return Err("Windows WebAuthn returned no assertion".into());
    }

    // SAFETY: `assertion` is a live allocation from the DLL, whose layout
    // matches `Assertion` for the V1 prefix read here.
    let output = unsafe {
        let a = &*assertion;
        let user_handle = {
            let uh = copy_bytes(a.pb_user_id, a.cb_user_id);
            if uh.is_empty() {
                None
            } else {
                Some(uh)
            }
        };
        AssertCeremonyOutput {
            credential_id: copy_bytes(a.credential.pb_id, a.credential.cb_id),
            authenticator_data: copy_bytes(a.pb_authenticator_data, a.cb_authenticator_data),
            signature: copy_bytes(a.pb_signature, a.cb_signature),
            user_handle,
        }
    };
    // SAFETY: the buffers were copied above; the allocation is now ours to free.
    unsafe { (api.free_assertion)(assertion) };

    if output.authenticator_data.is_empty() || output.signature.is_empty() {
        return Err("Windows WebAuthn returned an incomplete assertion".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_requirement_maps_webauthn_strings() {
        assert_eq!(user_verification_requirement("required"), 1);
        assert_eq!(user_verification_requirement("preferred"), 2);
        assert_eq!(user_verification_requirement("discouraged"), 3);
        // Unknown values must not become "any" (0) — that would let Windows
        // silently drop the RP's user-verification request.
        assert_eq!(user_verification_requirement("bogus"), 2);
    }

    #[test]
    fn attestation_preference_maps_webauthn_strings() {
        assert_eq!(attestation_preference("none"), 1);
        assert_eq!(attestation_preference("indirect"), 2);
        assert_eq!(attestation_preference("direct"), 3);
        assert_eq!(attestation_preference("enterprise"), 3);
        assert_eq!(attestation_preference("bogus"), 0);
    }

    #[test]
    fn resident_key_is_required_only_when_asked_for() {
        assert_eq!(require_resident_key("required"), 1);
        assert_eq!(require_resident_key("preferred"), 0);
        assert_eq!(require_resident_key("discouraged"), 0);
    }

    #[test]
    fn wide_strings_are_nul_terminated() {
        assert_eq!(to_wide("ab"), vec![97, 98, 0]);
        assert_eq!(to_wide(""), vec![0]);
    }

    #[test]
    fn wide_roundtrip() {
        let w = to_wide("localhost");
        // SAFETY: `to_wide` NUL-terminates.
        assert_eq!(unsafe { from_wide(w.as_ptr()) }.as_deref(), Some("localhost"));
        // SAFETY: null is an accepted input.
        assert_eq!(unsafe { from_wide(std::ptr::null()) }, None);
    }

    #[test]
    fn credential_list_pointers_match_their_entries() {
        let ids = vec![vec![1u8, 2, 3], vec![9u8; 32]];
        let credential_type = to_wide("public-key");
        let (entries, pointers) = credential_list(&ids, &credential_type);

        assert_eq!(entries.len(), 2);
        assert_eq!(pointers.len(), 2);
        for (i, ptr) in pointers.iter().enumerate() {
            // SAFETY: `entries` is still alive and owns these addresses.
            let entry = unsafe { &**ptr };
            assert_eq!(entry.cb_id as usize, ids[i].len());
            assert_eq!(entry.pb_id, ids[i].as_ptr());
            assert_eq!(entry.dw_transports, CTAP_TRANSPORT_USB);
            assert_eq!(entry.dw_version, CREDENTIAL_EX_VERSION_1);
        }
    }

    #[test]
    fn empty_credential_list_yields_no_pointers() {
        let credential_type = to_wide("public-key");
        let (entries, pointers) = credential_list(&[], &credential_type);
        assert!(entries.is_empty());
        assert!(pointers.is_empty());
    }

    #[test]
    fn timeout_saturates_instead_of_wrapping() {
        assert_eq!(timeout_ms(60_000), 60_000);
        assert_eq!(timeout_ms(u64::MAX), u32::MAX);
    }

    /// Proves the DLL name and the four exported symbols this module needs
    /// are spelled correctly, without running a ceremony or showing any UI.
    /// Ignored by default because it asserts something about the host OS
    /// rather than about this code: it needs a Windows that ships the
    /// WebAuthn platform API (1809+). Run with
    /// `cargo test -p bastion-vault-gui --lib fido2_windows -- --ignored`.
    #[test]
    #[ignore = "requires a Windows host with the WebAuthn platform API"]
    fn webauthn_dll_and_entry_points_resolve() {
        let api = api().expect("webauthn.dll should load on a supported Windows host");
        assert!(
            api.get_error_name.is_some(),
            "WebAuthNGetErrorName is part of the baseline API surface"
        );
    }

    /// The layouts are transcribed from `webauthn.h` by hand, so a wrong
    /// field order or a missing padding assumption is the failure mode with
    /// the worst consequences (the DLL reading garbage as a pointer). Pin the
    /// sizes and the offsets of every field the DLL reads or writes.
    #[test]
    fn struct_layouts_match_the_sdk_header() {
        use std::mem::{align_of, size_of};

        assert_eq!(size_of::<RpEntityInformation>(), 32);
        assert_eq!(size_of::<UserEntityInformation>(), 40);
        assert_eq!(size_of::<ClientData>(), 24);
        assert_eq!(size_of::<CoseCredentialParameter>(), 24);
        assert_eq!(size_of::<CoseCredentialParameters>(), 16);
        assert_eq!(size_of::<Credential>(), 24);
        assert_eq!(size_of::<Credentials>(), 16);
        assert_eq!(size_of::<CredentialEx>(), 32);
        assert_eq!(size_of::<CredentialList>(), 16);
        assert_eq!(size_of::<Extensions>(), 16);
        assert_eq!(size_of::<MakeCredentialOptions>(), 80);
        assert_eq!(size_of::<GetAssertionOptions>(), 88);
        assert_eq!(size_of::<CredentialAttestation>(), 96);
        assert_eq!(size_of::<Assertion>(), 72);

        assert_eq!(align_of::<MakeCredentialOptions>(), 8);
        assert_eq!(align_of::<Assertion>(), 8);

        assert_eq!(std::mem::offset_of!(Assertion, pb_authenticator_data), 8);
        assert_eq!(std::mem::offset_of!(Assertion, cb_signature), 16);
        assert_eq!(std::mem::offset_of!(Assertion, credential), 32);
        assert_eq!(std::mem::offset_of!(Assertion, cb_user_id), 56);
        assert_eq!(std::mem::offset_of!(Assertion, pb_user_id), 64);

        assert_eq!(
            std::mem::offset_of!(CredentialAttestation, pb_attestation_object),
            72
        );
        assert_eq!(
            std::mem::offset_of!(CredentialAttestation, cb_credential_id),
            80
        );
        assert_eq!(
            std::mem::offset_of!(CredentialAttestation, pb_credential_id),
            88
        );

        assert_eq!(
            std::mem::offset_of!(MakeCredentialOptions, p_exclude_credential_list),
            72
        );
        assert_eq!(
            std::mem::offset_of!(GetAssertionOptions, p_allow_credential_list),
            80
        );
    }
}
