"use client";

import { useRouter } from "next/navigation";

type ReportButtonProps = {
  mode?: "open" | "print";
};

export function ReportButton({ mode = "open" }: ReportButtonProps) {
  const router = useRouter();
  const label = mode === "print" ? "Skriv ut rapport" : "Generera rapport";

  return (
    <button
      type="button"
      onClick={() => (mode === "print" ? window.print() : router.push("/dashboard/report"))}
      className="inline-flex min-h-11 cursor-pointer items-center justify-center gap-2.5 rounded-sm bg-government px-5 py-2.5 text-sm font-bold text-white shadow-sm transition hover:bg-[#0b3025] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-government"
    >
      <svg aria-hidden="true" viewBox="0 0 24 24" className="size-4 fill-none stroke-current" strokeWidth="1.8">
        <path d="M7 3h7l3 3v5M7 3v8h10V6M6 14h12v7H6z" />
        <path d="M14 3v4h4" />
      </svg>
      {label}
    </button>
  );
}
