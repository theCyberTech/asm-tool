export function formatDate(value?: string): string {
  if (!value) {
    return "Never";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
  });
}

export function formatDateTime(value?: string): string {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

export function severityClass(severity: string): string {
  const key = severity.toLowerCase();
  switch (key) {
    case "critical":
    case "high":
    case "medium":
    case "low":
    case "info":
      return `severity severity-${key}`;
    default:
      return "severity severity-info";
  }
}
