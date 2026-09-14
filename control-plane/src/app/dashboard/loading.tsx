export default function DashboardLoading() {
  return (
    <div className="animate-pulse px-5 py-8 sm:px-8 lg:px-10">
      <div className="h-4 w-32 rounded bg-line" />
      <div className="mt-5 h-10 w-80 max-w-full rounded bg-line" />
      <div className="mt-10 grid gap-4 md:grid-cols-3">
        {[0, 1, 2].map((item) => (
          <div key={item} className="h-32 rounded-sm border border-line bg-panel" />
        ))}
      </div>
      <div className="mt-7 h-80 rounded-sm border border-line bg-panel" />
    </div>
  );
}
