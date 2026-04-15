import { useState, useCallback } from "react";

interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

export function useVaultApi<T>(apiFn: (...args: unknown[]) => Promise<T>) {
  const [state, setState] = useState<ApiState<T>>({
    data: null,
    loading: false,
    error: null,
  });

  const execute = useCallback(
    async (...args: unknown[]) => {
      setState({ data: null, loading: true, error: null });
      try {
        const data = await apiFn(...args);
        setState({ data, loading: false, error: null });
        return data;
      } catch (e: unknown) {
        const error = String(e);
        setState({ data: null, loading: false, error });
        throw e;
      }
    },
    [apiFn],
  );

  return { ...state, execute };
}
