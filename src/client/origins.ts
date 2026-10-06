/**
 * Resolves the browser-side origins the pairing page talks to.
 *
 * Both are overridable at build time (Vite reads VLINK_PUBLIC_ORIGIN and VLINK_ACCOUNT_ORIGIN,
 * see vite.config.ts); without configuration the historical veklom.com defaults apply.
 */
const DEFAULT_API_ORIGIN = "https://vlink.veklom.com";
const DEFAULT_ACCOUNT_ORIGIN = "https://veklom.com";
const FRONTEND_HOSTS = new Set(["veklom.com", "www.veklom.com"]);

const normalize = (configured: string | undefined) => configured?.trim().replace(/\/+$/, "") || undefined;

/** Origin the VLink API is called on; empty means same-origin relative requests. */
export const resolveApiOrigin = (hostname: string, configured?: string): string =>
  normalize(configured) ?? (FRONTEND_HOSTS.has(hostname) ? DEFAULT_API_ORIGIN : "");

/** Origin of the account frontend (sign-in, signup, onboarding); empty means relative links. */
export const resolveAccountOrigin = (hostname: string, configured?: string): string =>
  normalize(configured) ?? (hostname === new URL(DEFAULT_API_ORIGIN).hostname ? DEFAULT_ACCOUNT_ORIGIN : "");
