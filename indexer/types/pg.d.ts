declare module "pg" {
  export class Client {
    constructor(config?: unknown)
    connect(): Promise<void>
    end(): Promise<void>
    query<T = { rows: unknown[] }>(text: string, params?: unknown[]): Promise<{ rows: any[] }>
  }
}


