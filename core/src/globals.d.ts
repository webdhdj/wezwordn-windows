// Global Buffer declaration (normally supplied by @types/node, which this
// zero-dependency package deliberately does not use). Only the surface this
// package touches is declared.

interface ImportMeta {
  url: string;
}

declare class Buffer extends Uint8Array {
  static alloc(size: number, fill?: number): Buffer;
  static allocUnsafe(size: number): Buffer;
  static from(data: string, encoding?: string): Buffer;
  static from(data: readonly number[]): Buffer;
  static from(data: Uint8Array): Buffer;
  static from(data: ArrayBuffer): Buffer;
  static concat(list: readonly Buffer[]): Buffer;
  static compare(a: Buffer, b: Buffer): number;
  static isBuffer(value: unknown): value is Buffer;
  readonly length: number;
  subarray(start?: number, end?: number): Buffer;
  equals(other: Buffer): boolean;
  toString(encoding?: string): string;
  readUInt32BE(offset: number): number;
  writeUInt32BE(value: number, offset: number): number;
  readBigUInt64BE(offset?: number): bigint;
  writeBigUInt64BE(value: bigint, offset?: number): number;
  copy(target: Buffer, targetStart?: number): number;
  fill(value: number): this;
  [index: number]: number;
}

interface Uint8Array {
  // Node Buffers are Uint8Arrays; keep index access ergonomic in ported code.
}
