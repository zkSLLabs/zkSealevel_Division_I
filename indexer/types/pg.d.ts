declare module "pg" {
  export class Client {
    constructor(config?: unknown);
    connect(): Promise<void>;
    end(): Promise<void>;
    query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount?: number }>;
  }
}


