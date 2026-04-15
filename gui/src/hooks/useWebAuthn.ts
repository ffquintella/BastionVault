import { useCallback } from "react";
import * as api from "../lib/api";
import type { Fido2LoginResponse } from "../lib/types";

/**
 * Hook for FIDO2/WebAuthn operations.
 *
 * Uses native Tauri CTAP2 commands that talk directly to USB security keys
 * via the Mozilla `authenticator` crate, bypassing the browser's
 * `navigator.credentials` API (which is unavailable in Tauri's WebView).
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
