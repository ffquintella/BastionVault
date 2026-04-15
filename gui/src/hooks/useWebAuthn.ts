import { useCallback } from "react";
import * as api from "../lib/api";
import type { Fido2LoginResponse } from "../lib/types";

/**
 * Base64URL encode/decode helpers for WebAuthn ArrayBuffer round-trips.
 * WebAuthn challenges and credential IDs are transmitted as base64url strings
 * from the server (webauthn-rs), but the browser API expects ArrayBuffers.
 */
function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Recursively convert base64url strings in challenge JSON to ArrayBuffers
 * for fields that the browser WebAuthn API expects as BufferSource.
 */
function prepareCreationOptions(serverData: Record<string, unknown>): CredentialCreationOptions {
  const publicKey = serverData.publicKey as Record<string, unknown> ?? serverData;

  // challenge must be ArrayBuffer
  if (typeof publicKey.challenge === "string") {
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  }

  // user.id must be ArrayBuffer
  const user = publicKey.user as Record<string, unknown> | undefined;
  if (user && typeof user.id === "string") {
    user.id = base64urlToBuffer(user.id);
  }

  // excludeCredentials[].id must be ArrayBuffer
  const excludeCredentials = publicKey.excludeCredentials as Array<Record<string, unknown>> | undefined;
  if (excludeCredentials) {
    for (const cred of excludeCredentials) {
      if (typeof cred.id === "string") {
        cred.id = base64urlToBuffer(cred.id);
      }
    }
  }

  return { publicKey } as unknown as CredentialCreationOptions;
}

function prepareRequestOptions(serverData: Record<string, unknown>): CredentialRequestOptions {
  const publicKey = serverData.publicKey as Record<string, unknown> ?? serverData;

  if (typeof publicKey.challenge === "string") {
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
  }

  const allowCredentials = publicKey.allowCredentials as Array<Record<string, unknown>> | undefined;
  if (allowCredentials) {
    for (const cred of allowCredentials) {
      if (typeof cred.id === "string") {
        cred.id = base64urlToBuffer(cred.id);
      }
    }
  }

  return { publicKey } as unknown as CredentialRequestOptions;
}

/**
 * Serialize a browser PublicKeyCredential to JSON string for the backend.
 */
function serializeCredential(credential: PublicKeyCredential): string {
  const response = credential.response;

  const result: Record<string, unknown> = {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {} as Record<string, unknown>,
  };

  const resp = result.response as Record<string, unknown>;

  if ("attestationObject" in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    resp.attestationObject = bufferToBase64url(attestation.attestationObject);
    resp.clientDataJSON = bufferToBase64url(attestation.clientDataJSON);
  } else {
    const assertion = response as AuthenticatorAssertionResponse;
    resp.authenticatorData = bufferToBase64url(assertion.authenticatorData);
    resp.clientDataJSON = bufferToBase64url(assertion.clientDataJSON);
    resp.signature = bufferToBase64url(assertion.signature);
    if (assertion.userHandle) {
      resp.userHandle = bufferToBase64url(assertion.userHandle);
    }
  }

  return JSON.stringify(result);
}

/**
 * Hook that encapsulates the WebAuthn browser ceremony.
 */
export function useWebAuthn() {
  const register = useCallback(async (username: string): Promise<void> => {
    // Step 1: Get challenge from backend.
    const beginResp = await api.fido2RegisterBegin(username);
    const options = prepareCreationOptions(beginResp.data);

    // Step 2: Browser ceremony.
    const credential = await navigator.credentials.create(options);
    if (!credential) {
      throw new Error("Registration cancelled or no credential returned");
    }

    // Step 3: Send response to backend.
    const credentialJson = serializeCredential(credential as PublicKeyCredential);
    await api.fido2RegisterComplete(username, credentialJson);
  }, []);

  const authenticate = useCallback(async (username: string): Promise<Fido2LoginResponse> => {
    // Step 1: Get challenge from backend.
    const beginResp = await api.fido2LoginBegin(username);
    const options = prepareRequestOptions(beginResp.data);

    // Step 2: Browser ceremony.
    const credential = await navigator.credentials.get(options);
    if (!credential) {
      throw new Error("Authentication cancelled or no credential returned");
    }

    // Step 3: Send response to backend, receive token.
    const credentialJson = serializeCredential(credential as PublicKeyCredential);
    return await api.fido2LoginComplete(username, credentialJson);
  }, []);

  return { register, authenticate };
}
