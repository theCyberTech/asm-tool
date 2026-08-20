const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

export function extractEmails(text: string, domain: string): string[] {
  const matches = text.match(EMAIL_RE) ?? [];
  return [
    ...new Set(
      matches
        .map((item) => item.toLowerCase())
        .filter((email) => {
          const host = email.split("@")[1] ?? "";
          return host === domain || host.endsWith(`.${domain}`);
        }),
    ),
  ];
}
