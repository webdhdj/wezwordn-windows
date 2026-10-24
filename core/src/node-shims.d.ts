// Minimal local declarations for the Node.js built-ins this package uses.
// The package has ZERO npm dependencies (including no @types/node), so the
// exact subset of node:crypto / node:fs / node:path / node:test /
// node:assert used here is declared in this one file.

declare module "node:crypto" {
  export interface KeyObject {
    readonly type: string;
    export(options: { type: string; format: string }): Buffer;
  }
  export interface Hash {
    update(data: Buffer | string): Hash;
    digest(): Buffer;
    digest(encoding: "hex"): string;
  }
  export interface Hmac {
    update(data: Buffer | string): Hmac;
    digest(): Buffer;
  }
  export interface Cipher {
    update(data: Buffer): Buffer;
    final(): Buffer;
    getAuthTag(): Buffer;
  }
  export interface Decipher {
    update(data: Buffer): Buffer;
    final(): Buffer;
    setAuthTag(tag: Buffer): void;
  }
  export function createHash(algorithm: string): Hash;
  export function createHmac(algorithm: string, key: Buffer): Hmac;
  export function createCipheriv(algorithm: string, key: Buffer, iv: Buffer): Cipher;
  export function createDecipheriv(algorithm: string, key: Buffer, iv: Buffer): Decipher;
  export function randomBytes(size: number): Buffer;
  export function randomUUID(): string;
  export function pbkdf2Sync(
    password: string | Buffer,
    salt: Buffer,
    iterations: number,
    keylen: number,
    digest: string,
  ): Buffer;
  export function hkdfSync(
    digest: string,
    ikm: Buffer,
    salt: Buffer,
    info: Buffer,
    keylen: number,
  ): ArrayBuffer;
  export function generateKeyPairSync(
    type: "x25519",
  ): { publicKey: KeyObject; privateKey: KeyObject };
  export function createPublicKey(options: {
    key: Buffer;
    format: string;
    type: string;
  }): KeyObject;
  export function createPrivateKey(options: {
    key: Buffer;
    format: string;
    type: string;
  }): KeyObject;
  export function diffieHellman(options: {
    privateKey: KeyObject;
    publicKey: KeyObject;
  }): Buffer;
}

declare module "node:fs" {
  export function readFileSync(path: string): Buffer;
  export function readFileSync(path: string, encoding: string): string;
  export function writeFileSync(path: string, data: Buffer | string): void;
  export function existsSync(path: string): boolean;
  export function mkdirSync(path: string, options?: { recursive?: boolean }): void;
  export function rmSync(path: string, options?: { force?: boolean; recursive?: boolean }): void;
  export function renameSync(oldPath: string, newPath: string): void;
  export function copyFileSync(src: string, dest: string): void;
  export function openSync(path: string, flags: string): number;
  export function closeSync(fd: number): void;
  export function readSync(fd: number, buffer: Buffer, offset: number, length: number, position: number | null): number;
  export function writeSync(fd: number, buffer: Buffer, offset?: number, length?: number): number;
  export function fsyncSync(fd: number): void;
  export function mkdtempSync(prefix: string): string;
}

declare module "node:path" {
  export function join(...parts: string[]): string;
  export function dirname(path: string): string;
  export function basename(path: string): string;
}

declare module "node:os" {
  export function tmpdir(): string;
}

declare module "node:url" {
  export function fileURLToPath(url: URL): string;
}

declare module "node:test" {
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
  export function beforeEach(fn: () => void): void;
  export function afterEach(fn: () => void): void;
}

declare module "node:assert/strict" {
  export function equal(actual: unknown, expected: unknown, message?: string): void;
  export function notEqual(actual: unknown, expected: unknown, message?: string): void;
  export function deepEqual(actual: unknown, expected: unknown, message?: string): void;
  export function ok(value: unknown, message?: string): void;
  export function throws(fn: () => unknown, error?: unknown, message?: string): void;
}
