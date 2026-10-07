import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router";

import type { ProviderAccountsLink } from "../components/ProviderAccountPicker";
import * as api from "../lib/api";
import { extractError } from "../lib/error";
import { providerAccountsRoute } from "../lib/credentialProviders";
import { usePluginSurfacesStore } from "../stores/pluginSurfacesStore";

/**
 * The approved, active credential providers (features/self-accounts.md §6),
 * read once each time `enabled` turns on. A failure — an older server without
 * `resources/v2/connect/providers`, or a narrowed policy — leaves the list
 * empty: nothing is offered, and `error` says why.
 */
export function useCredentialProviders(enabled: boolean): {
  providers: api.CredentialProviderInfo[];
  loaded: boolean;
  error: string | null;
} {
  const [providers, setProviders] = useState<api.CredentialProviderInfo[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setLoaded(false);
    api
      .connectCredentialProviders()
      .then((list) => {
        if (cancelled) return;
        setProviders(list);
        setError(null);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setProviders([]);
        setError(extractError(e));
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled]);
  return { providers, loaded, error };
}

/**
 * The picker's "Add an account" link for the main window: the provider
 * plugin's own management page, when its surface is registered. The session
 * windows have no plugin pages, so they pass no link.
 */
export function useProviderAccountsLink(): ProviderAccountsLink {
  const navigate = useNavigate();
  const bundle = usePluginSurfacesStore((s) => s.bundle);
  return useCallback(
    (provider: string) => {
      const route = providerAccountsRoute(bundle, provider);
      return route ? () => navigate(route) : null;
    },
    [bundle, navigate],
  );
}
