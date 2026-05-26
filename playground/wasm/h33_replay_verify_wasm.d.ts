/* tslint:disable */
/* eslint-disable */

export function _start(): void;

/**
 * Compute SHA3-256 of a `Uint8Array` as a 64-char lowercase hex string.
 *
 * Used by the browser playground to cross-check that a signed transcript
 * describes the exact bundle file the user dropped in. Mirrors the CLI's
 * `--verify-transcript <bundle.json>` cross-check semantics.
 */
export function sha3_256Hex(bytes: Uint8Array): string;

/**
 * Verifier version string (matches the CLI's `VERIFIER_VERSION`).
 */
export function verifierVersion(): string;

/**
 * Run the 10-check protocol over a JSON-encoded `ReplayBundle`.
 *
 * Returns a `VerifyReport` serialized as a JS object. Throws a JS `Error`
 * if the JSON fails to parse — callers should treat that as a separate
 * failure mode (parse error vs verification fail).
 *
 * `strict` mirrors the CLI's `--strict` flag. The browser has no payloads
 * directory, so check #3 (merkle_roots) is always skipped — in strict mode
 * the skip becomes a check failure.
 */
export function verifyBundle(bundle_json: string, strict: boolean): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly _start: () => void;
    readonly sha3_256Hex: (a: number, b: number) => [number, number];
    readonly verifierVersion: () => [number, number];
    readonly verifyBundle: (a: number, b: number, c: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
