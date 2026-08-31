import { useState, useCallback, createContext, useContext, type ReactNode } from "react";

type ToastType = "success" | "error" | "info";

interface Toast {
  id: number;
  type: ToastType;
  message: string;
}

interface ToastContextValue {
  toast: (type: ToastType, message: string) => void;
}

const ToastContext = createContext<ToastContextValue>({
  toast: () => {},
});

export function useToast() {
  return useContext(ToastContext);
}

let nextId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((type: ToastType, message: string) => {
    const id = nextId++;
    setToasts((prev) => [...prev, { id, type, message }]);
    // Error toasts stay on screen longer than success/info ones —
    // they carry actionable information the user usually wants to read
    // (and copy / screenshot for support). Success/info auto-dismiss
    // at 4 s; errors stay for 8 s. The `×` close button always wins.
    const dismissAfter = type === "error" ? 8000 : 4000;
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, dismissAfter);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const typeStyles: Record<ToastType, string> = {
    success: "border-green-500/40 bg-green-500/10 text-green-400",
    error: "border-red-500/40 bg-red-500/10 text-red-400",
    info: "border-blue-500/40 bg-blue-500/10 text-blue-400",
  };

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      {/* `w-` pins the stack's width instead of letting it shrink-to-fit:
          with only `max-w-sm` the flex row's min-content width wins (a
          flex item defaults to `min-width: auto`), so one unbreakable
          token — a cargo checkout path, a docs.rs URL, both of which
          appear verbatim in RDP connector errors — pushed the toast
          past the right edge of the window and cut every line off
          mid-sentence. `min-w-0` + `break-words` on the message let
          those tokens wrap instead. */}
      <div className="fixed bottom-4 right-4 z-[100] space-y-2 w-[min(24rem,calc(100vw-2rem))]">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`flex items-start gap-2 px-4 py-3 rounded-lg border text-sm shadow-lg backdrop-blur-sm ${typeStyles[t.type]}`}
          >
            <span className="flex-1 min-w-0 break-words">{t.message}</span>
            <button
              onClick={() => removeToast(t.id)}
              className="opacity-60 hover:opacity-100 shrink-0"
            >
              &times;
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
