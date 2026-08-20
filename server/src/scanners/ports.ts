import net from "node:net";

const SERVICE_NAMES: Record<number, string> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  445: "smb",
  3306: "mysql",
  3389: "rdp",
  5432: "postgres",
  8080: "http-alt",
  8443: "https-alt",
};

export type OpenPort = {
  port: number;
  protocol: "tcp";
  state: "open";
  service: string;
  banner: string;
};

export function probePort(host: string, port: number, timeoutMs = 1500): Promise<OpenPort | null> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (result: OpenPort | null) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      finish({
        port,
        protocol: "tcp",
        state: "open",
        service: SERVICE_NAMES[port] ?? "",
        banner: "",
      });
    });
    socket.once("error", () => {
      clearTimeout(timer);
      finish(null);
    });
  });
}

export async function scanPorts(host: string, ports: number[], concurrency = 40): Promise<OpenPort[]> {
  const open: OpenPort[] = [];
  let index = 0;
  async function worker(): Promise<void> {
    while (index < ports.length) {
      const current = index;
      index += 1;
      const port = ports[current];
      if (port === undefined) {
        continue;
      }
      const result = await probePort(host, port);
      if (result) {
        open.push(result);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, () => worker()));
  return open.sort((a, b) => a.port - b.port);
}
