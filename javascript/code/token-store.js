import { readFile, writeFile, unlink } from 'node:fs/promises';

// Any object with load(), save(tokens) and clear() works as a token store.
// tokens is { accessToken, refreshToken, expiresAt } with expiresAt as epoch milliseconds.

// Electron: encrypted with the OS keychain via safeStorage
export class SafeStorageTokenStore {
  constructor(safeStorage, filePath) {
    this.safeStorage = safeStorage;
    this.filePath = filePath;   // e.g. path.join(app.getPath('userData'), 'datazap-tokens.bin')
  }

  async load() {
    try {
      const encrypted = await readFile(this.filePath);
      return JSON.parse(this.safeStorage.decryptString(encrypted));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async save(tokens) {
    await writeFile(this.filePath, this.safeStorage.encryptString(JSON.stringify(tokens)));
  }

  async clear() {
    await unlink(this.filePath).catch(err => { if (err.code !== 'ENOENT') throw err; });
  }
}

// Development only: plaintext JSON on disk
export class FileTokenStore {
  constructor(filePath) { this.filePath = filePath; }
  async load() {
    try { return JSON.parse(await readFile(this.filePath, 'utf8')); }
    catch (err) { if (err.code === 'ENOENT') return null; throw err; }
  }
  async save(tokens) { await writeFile(this.filePath, JSON.stringify(tokens)); }
  async clear() { await unlink(this.filePath).catch(err => { if (err.code !== 'ENOENT') throw err; }); }
}
