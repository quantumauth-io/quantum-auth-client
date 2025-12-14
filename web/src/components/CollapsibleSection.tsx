import { useEffect, useState, type ReactNode } from "react";

type Props = {
    title: string;
    indicatorColor: "limegreen" | "tomato";
    indicatorTitle?: string;
    defaultOpen?: boolean;
    storageKey?: string;
    children: ReactNode;
};

export function CollapsibleSection({
                                       title,
                                       indicatorColor,
                                       indicatorTitle,
                                       defaultOpen = true,
                                       storageKey,
                                       children,
                                   }: Props) {
    const [open, setOpen] = useState<boolean>(() => {
        if (!storageKey) return defaultOpen;
        const v = localStorage.getItem(storageKey);
        if (v === "1") return true;
        if (v === "0") return false;
        return defaultOpen;
    });

    useEffect(() => {
        if (!storageKey) return;
        localStorage.setItem(storageKey, open ? "1" : "0");
    }, [open, storageKey]);

    return (
        <div className="w-full rounded-xl border border-white/10 overflow-hidden m-3">
            {/* Header */}
            <div
                role="button"
                tabIndex={0}
                onClick={() => setOpen((v) => !v)}
                onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") setOpen((v) => !v);
                }}
                aria-expanded={open}
                className={[
                    "w-full",
                    "px-5 py-4",
                    "flex items-center justify-between gap-3",
                    "cursor-pointer select-none",
                    open ? "bg-white/[0.05]" : "bg-transparent",
                    "hover:bg-white/[0.04]",
                    "transition-colors",
                ].join(" ")}
            >
                <div className="flex items-center gap-3">
                    <h2 className="m-0 text-2xl font-semibold leading-tight">{title}</h2>
                    <span
                        title={indicatorTitle}
                        className="inline-block h-2.5 w-2.5 rounded-full"
                        style={{ background: indicatorColor }}
                    />
                </div>

                <span
                    aria-hidden
                    className={[
                        "select-none text-xl text-white/70",
                        "transition-transform duration-150",
                        open ? "rotate-0" : "-rotate-90",
                    ].join(" ")}
                >
          ▾
        </span>
            </div>

            {/* Body — ALWAYS mounted, animated */}
            <div
                className={[
                    "grid transition-[grid-template-rows] duration-200 ease-out",
                    open ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
                ].join(" ")}
            >
                <div className="overflow-hidden">
                    <div className="w-full px-5 pb-5 bg-white/[0.025]">
                        {children}
                    </div>
                </div>
            </div>
        </div>
    );
}
