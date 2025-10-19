declare module "dotenv" {
  export interface DotenvConfigOptions { path?: string }
  export function config(options?: DotenvConfigOptions): void
  const _default: { config: typeof config }
  export default _default
}


