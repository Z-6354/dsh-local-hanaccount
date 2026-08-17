import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';

/** Cordis plugin name used by the DSH loader. */
export const name = 'loacal-hanaccount';

/** Configuration for the local Han account plugin. */
export interface Config {
  /** Account identifier used by the local profile. */
  accountName?: string;
  /** Human-readable display name. */
  displayName?: string;
  /** Optional contact email attached to the profile. */
  email?: string;
  /** Free-form notes for downstream local account integrations. */
  notes?: string;
}

/** Schemastery schema consumed by Cordis/DSH plugin loaders. */
export const Config: z<Config> = z.object({
  accountName: z.string().default('hanaccount').description('Local account identifier.'),
  displayName: z.string().default('Han Account').description('Display name for the local account.'),
  email: z.string().default('').description('Optional email address.'),
  notes: z.string().default('').description('Optional notes for local integrations.'),
});

/**
 * Install the plugin.
 *
 * This first release intentionally keeps the runtime side-effect free: it gives
 * DSH a typed, loadable package and a stable configuration surface that later
 * releases can extend with account-specific services or UI integrations.
 */
export function apply(_ctx: Context, _config: Config = {}): void {
  // Reserved for future DSH local-account integration.
}
