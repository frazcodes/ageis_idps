declare module "fs" {
  export function existsSync(path: string): boolean;
  export function readFileSync(path: string, encoding: string): string;
}

declare module "path" {
  export function join(...paths: string[]): string;
}

declare module "crypto" {
  export interface Signer {
    update(data: string | any): void;
    sign(privateKey: string, outputEncoding: "base64url" | "base64" | "hex"): string;
  }
  export function createSign(algorithm: string): Signer;
}

declare namespace NodeJS {
  interface ProcessEnv {
    [key: string]: string | undefined;
  }
  interface Process {
    env: ProcessEnv;
    cwd(): string;
  }
}

declare var process: NodeJS.Process;

interface BufferInstance {
  toString(encoding?: string): string;
}

declare var Buffer: {
  from(str: string, encoding?: string): BufferInstance;
};

