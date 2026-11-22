// A bare WebSocket client over TLS, so tests can act as a hostile or stuck
// peer: custom headers, raw frames, and a socket that stops reading.
import { randomBytes } from "node:crypto";
import tls from "node:tls";
import { PORT } from "./harness";

export class RawSocket {
  private buffer = Buffer.alloc(0);
  private messages: string[] = [];
  private waiters: (() => void)[] = [];
  closed = false;
  /** Close code the peer sent, if any. */
  closeCode?: number;

  private constructor(private socket: tls.TLSSocket) {
    socket.on("data", (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.parse();
    });
    const end = () => {
      this.closed = true;
      this.wake();
    };
    socket.on("close", end);
    socket.on("error", end);
  }

  /** Upgrades `path`; resolves the HTTP status and, on 101, the socket. */
  static open(
    path: string,
    headers: Record<string, string>,
  ): Promise<{ status: number; socket?: RawSocket }> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: "127.0.0.1",
        port: PORT,
        rejectUnauthorized: false,
        ALPNProtocols: ["http/1.1"],
      });
      let head = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        head = Buffer.concat([head, chunk]);
        const end = head.indexOf("\r\n\r\n");
        if (end < 0) return;
        socket.off("data", onData);
        const status = Number(/^HTTP\/1\.1 (\d+)/.exec(head.toString())?.[1]);
        if (status !== 101) {
          socket.destroy();
          resolve({ status });
          return;
        }
        const raw = new RawSocket(socket);
        raw.buffer = head.subarray(end + 4);
        raw.parse();
        resolve({ status, socket: raw });
      };
      socket.on("data", onData);
      socket.on("error", reject);
      socket.on("secureConnect", () => {
        const lines = [
          `GET ${path} HTTP/1.1`,
          `Host: 127.0.0.1:${PORT}`,
          "Connection: Upgrade",
          "Upgrade: websocket",
          "Sec-WebSocket-Version: 13",
          `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`,
          ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
        ];
        socket.write(`${lines.join("\r\n")}\r\n\r\n`);
      });
    });
  }

  private wake() {
    for (const waiter of this.waiters.splice(0)) waiter();
  }

  private parse() {
    for (;;) {
      if (this.buffer.length < 2) return;
      const opcode = this.buffer[0] & 0x0f;
      let length = this.buffer[1] & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.length < 4) return;
        length = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.length < 10) return;
        length = Number(this.buffer.readBigUInt64BE(2));
        offset = 10;
      }
      if (this.buffer.length < offset + length) return;
      const payload = this.buffer.subarray(offset, offset + length);
      this.buffer = this.buffer.subarray(offset + length);
      if (opcode === 1) this.messages.push(payload.toString("utf8"));
      else if (opcode === 9) this.frame(10, payload);
      else if (opcode === 8) {
        if (payload.length >= 2) this.closeCode = payload.readUInt16BE(0);
        this.socket.end();
      }
      this.wake();
    }
  }

  private frame(opcode: number, payload: Buffer) {
    if (this.closed) return false;
    const mask = randomBytes(4);
    let header: Buffer;
    if (payload.length < 126) {
      header = Buffer.from([0x80 | opcode, 0x80 | payload.length]);
    } else if (payload.length < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(payload.length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2);
    }
    const masked = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++)
      masked[i] = payload[i] ^ mask[i % 4];
    return this.socket.write(Buffer.concat([header, mask, masked]));
  }

  send(value: unknown) {
    return this.frame(1, Buffer.from(JSON.stringify(value)));
  }

  sendBinary(data: Buffer) {
    return this.frame(2, data);
  }

  /** Next JSON text message matching `want`, or null on close/timeout. */
  async next(
    want: (message: {
      type?: string;
      [key: string]: unknown;
    }) => boolean = () => true,
    timeoutMs = 10_000,
  ): Promise<Record<string, unknown> | null> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      while (this.messages.length > 0) {
        const message = JSON.parse(this.messages.shift() ?? "{}");
        if (want(message)) return message;
      }
      const left = deadline - Date.now();
      if (this.closed || left <= 0) return null;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, left);
        this.waiters.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }

  /** Stops reading; the peer's writes then back up. */
  pause() {
    this.socket.pause();
  }

  close() {
    this.socket.destroy();
  }
}
