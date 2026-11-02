declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: any;
  }
  interface Element {
    [key: string]: any;
  }
}

declare namespace React {
  type ReactNode = any;
  type ReactElement = any;
  type FormEvent<T = any> = { preventDefault(): void; [key: string]: any };
  type ChangeEvent<T = any> = { target: { value: any }; [key: string]: any };
}

declare module "react" {
  export type ReactNode = any;
  export type ReactElement = any;
  export type FormEvent<T = any> = { preventDefault(): void; [key: string]: any };
  export type ChangeEvent<T = any> = { target: { value: any }; [key: string]: any };
  export function useState<T>(initialState: T | (() => T)): [T, (newState: T | ((prev: T) => T)) => void];
  export function useEffect(effect: () => void | (() => void), deps?: readonly any[]): void;
  export function useCallback<T extends (...args: any[]) => any>(callback: T, deps: readonly any[]): T;
  export function useMemo<T>(factory: () => T, deps: readonly any[] | undefined): T;
  export function useRef<T>(initialValue?: T): { current: T };
  const React: any;
  export default React;
}

declare module "react-dom" {
  const ReactDOM: any;
  export default ReactDOM;
}

declare module "lucide-react" {
  export const Shield: any;
  export const Key: any;
  export const Users: any;
  export const Clock: any;
  export const AlertTriangle: any;
  export const CheckCircle2: any;
  export const XCircle: any;
  export const Copy: any;
  export const Plus: any;
  export const RefreshCw: any;
  export const Power: any;
  export const Laptop: any;
  export const Calendar: any;
  export const Search: any;
  export const Trash2: any;
  export const Check: any;
  export const Building: any;
  export const Mail: any;
  export const FileText: any;
  export const RotateCcw: any;
  export const Lock: any;
  export const Eye: any;
  export const EyeOff: any;
  export const LogOut: any;
  export const Sparkles: any;
  export const ExternalLink: any;
  export const ChevronRight: any;
  export const UserCheck: any;
  export const Activity: any;
  export const Cpu: any;
  export const Terminal: any;
  export const Radio: any;
  export const Globe: any;
  export const LucideIcon: any;
  const icons: Record<string, any>;
  export default icons;
}
