import Link from "next/link";

export function DashboardShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-paper text-ink">
      <header className="print-hidden border-b border-line bg-panel">
        <div className="mx-auto flex h-18 max-w-[1440px] items-center justify-between px-5 sm:px-8">
          <Link href="/dashboard" className="flex items-center gap-3" aria-label="Aiproxy översikt">
            <span className="grid size-9 place-items-center rounded-sm bg-government font-serif text-lg font-bold text-white">
              A
            </span>
            <span>
              <span className="block text-sm font-bold tracking-tight">Aiproxy Compliance</span>
              <span className="block text-[10px] font-bold uppercase tracking-[0.18em] text-muted">
                Control Plane
              </span>
            </span>
          </Link>
          <div className="flex items-center gap-3 text-xs text-muted">
            <span className="hidden items-center gap-2 sm:flex">
              <span className="size-2 rounded-full bg-[#277553]" /> Systemet är i drift
            </span>
            <span className="h-5 w-px bg-line" />
            <span className="grid size-8 place-items-center rounded-full border border-line bg-white font-bold text-government">
              DS
            </span>
          </div>
        </div>
      </header>
      <div className="mx-auto flex max-w-[1440px]">
        <aside className="print-hidden hidden min-h-[calc(100vh-4.5rem)] w-64 shrink-0 border-r border-line bg-panel p-5 lg:block">
          <p className="mb-3 px-3 text-[10px] font-bold uppercase tracking-[0.18em] text-muted">
            Styrning
          </p>
          <nav aria-label="Huvudnavigation" className="space-y-1">
            <Link
              href="/dashboard"
              className="flex items-center gap-3 rounded-sm bg-government-light px-3 py-2.5 text-sm font-bold text-government"
            >
              <InventoryIcon /> AI-inventering
            </Link>
            <Link
              href="/dashboard/report"
              className="flex items-center gap-3 rounded-sm px-3 py-2.5 text-sm text-muted hover:bg-white hover:text-ink"
            >
              <DocumentIcon /> Bevisrapport
            </Link>
          </nav>
          <div className="mt-10 border-t border-line pt-5">
            <p className="px-3 text-xs leading-5 text-muted">
              Endast anonymiserad och kryptografiskt signerad telemetri visas.
            </p>
          </div>
        </aside>
        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  );
}

function InventoryIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="size-4 fill-none stroke-current" strokeWidth="1.8">
      <rect x="3" y="4" width="18" height="16" rx="1" />
      <path d="M8 9h8M8 14h8" />
    </svg>
  );
}

function DocumentIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="size-4 fill-none stroke-current" strokeWidth="1.8">
      <path d="M6 3h8l4 4v14H6z" />
      <path d="M14 3v5h5M9 13h6M9 17h6" />
    </svg>
  );
}
