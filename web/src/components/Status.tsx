export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="empty-state">
      <div className="spinner" aria-hidden="true" />
      <p className="mt-md">{label}…</p>
    </div>
  );
}

export function ErrorAlert({ message }: { message: string }) {
  return <div className="alert alert-danger">{message}</div>;
}

export function WarningAlert({ message }: { message: string }) {
  return <div className="alert alert-warning">{message}</div>;
}
