import tls from "node:tls";

export type CertificateResult = {
  host: string;
  port: number;
  subject: string;
  issuer: string;
  notAfter: string;
  daysUntilExpiry: number;
  san: string;
};

export function checkCertificate(host: string, port = 443, timeoutMs = 8000): Promise<CertificateResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || Object.keys(cert).length === 0) {
          reject(new Error(`no certificate for ${host}`));
          return;
        }
        const notAfter = cert.valid_to ? new Date(cert.valid_to) : new Date();
        const days = Math.round((notAfter.getTime() - Date.now()) / 86_400_000);
        const subjectCN = cert.subject?.CN;
        const issuerCN = cert.issuer?.CN;
        const san = Array.isArray(cert.subjectaltname)
          ? cert.subjectaltname.join(", ")
          : String(cert.subjectaltname ?? "");
        resolve({
          host,
          port,
          subject: Array.isArray(subjectCN) ? subjectCN.join(", ") : subjectCN || JSON.stringify(cert.subject ?? {}),
          issuer: Array.isArray(issuerCN) ? issuerCN.join(", ") : issuerCN || JSON.stringify(cert.issuer ?? {}),
          notAfter: notAfter.toISOString(),
          daysUntilExpiry: days,
          san,
        });
      },
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error(`certificate check timed out for ${host}`));
    });
    socket.on("error", (err) => {
      reject(err);
    });
  });
}
