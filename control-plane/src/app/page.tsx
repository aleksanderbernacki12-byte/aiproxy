import styles from "./page.module.css";

const controls = [
  ["Cryptographic evidence", "ECDSA P-256 · RFC 8785"],
  ["Data boundary", "Anonymous telemetry only"],
  ["Chain processing", "Buffered · Ordered · Verified"],
];

export default function Home() {
  return (
    <main className={styles.shell}>
      <header className={styles.header}>
        <div className={styles.brand}>
          <span className={styles.mark}>A</span>
          <span>Aiproxy</span>
        </div>
        <span className={styles.environment}>Control Plane</span>
      </header>

      <section className={styles.hero}>
        <p className={styles.eyebrow}>Enterprise AI compliance</p>
        <h1>Evidence your DPO can trust.</h1>
        <p className={styles.lead}>
          Verify AI activity without collecting customer prompts. Signed,
          chained telemetry stays separate from raw evidence in the customer
          data plane.
        </p>
        <div className={styles.status}>
          <span className={styles.statusDot} />
          Telemetry ingestion foundation ready
        </div>
      </section>

      <section className={styles.grid} aria-label="Compliance controls">
        {controls.map(([title, detail], index) => (
          <article className={styles.card} key={title}>
            <span className={styles.number}>0{index + 1}</span>
            <h2>{title}</h2>
            <p>{detail}</p>
          </article>
        ))}
      </section>

      <footer className={styles.footer}>
        <span>Designed for Data Protection Officers</span>
        <span>No plaintext prompts enter this system</span>
      </footer>
    </main>
  );
}
