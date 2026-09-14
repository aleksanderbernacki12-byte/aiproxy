export default async function LoginPage({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams;
  return (
    <main className="grid min-h-screen place-items-center bg-paper px-5 text-ink">
      <section className="w-full max-w-md rounded-sm border border-line bg-panel p-8 shadow-[0_8px_30px_rgba(20,32,25,0.08)]">
        <div className="grid size-11 place-items-center rounded-sm bg-government font-serif text-xl font-bold text-white">A</div>
        <p className="mt-7 text-[10px] font-bold uppercase tracking-[0.18em] text-government">DPO-portal</p>
        <h1 className="mt-2 font-serif text-3xl">Säker inloggning</h1>
        <p className="mt-3 text-sm leading-6 text-muted">Ange organisationens separata DPO-åtkomstnyckel.</p>
        {error && <p role="alert" className="mt-5 rounded-sm bg-alert-light px-4 py-3 text-sm text-alert">Ogiltig åtkomstnyckel.</p>}
        <form action="/api/dashboard/session" method="post" className="mt-6">
          <label htmlFor="access_key" className="text-xs font-bold">Åtkomstnyckel</label>
          <input id="access_key" name="access_key" type="password" required autoComplete="current-password" className="mt-2 w-full rounded-sm border border-line bg-white px-3 py-2.5 text-sm outline-none focus:border-government" />
          <button className="mt-5 w-full rounded-sm bg-government px-4 py-2.5 text-sm font-bold text-white">Logga in</button>
        </form>
      </section>
    </main>
  );
}
