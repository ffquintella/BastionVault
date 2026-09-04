import { useCallback } from "react";
import * as api from "../lib/api";
import type { Fido2LoginResponse } from "../lib/types";

/**
 * Hook for FIDO2/WebAuthn operations.
 *
 * Uses native Tauri commands rather than the browser's `navigator.credentials`
 * API, which is unavailable in Tauri's WebView. The backend picks the
 * transport per platform: the Windows WebAuthn platform API on Windows (the
 * OS holds FIDO USB devices open exclusively there), CTAP2 over raw USB HID
 * everywhere else. On Windows the OS renders its own insert/tap/PIN dialog,
 * so the only progress event is `os-prompt`.
 */
export function useWebAuthn() {
  const register = useCallback(async (username: string): Promise<void> => {
    await api.fido2NativeRegister(username);
  }, []);

  const authenticate = useCallback(async (username: string): Promise<Fido2LoginResponse> => {
    return await api.fido2NativeLogin(username);
  }, []);

  return { register, authenticate };
}
