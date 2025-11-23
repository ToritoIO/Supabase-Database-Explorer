export const cloudConfig = {
  /**
   * Ordered list of possible cloud origins. The extension will try them until one responds.
   * Update this list (or set sbde_cloud_origin_override in storage) if you run the cloud app elsewhere.
   */
  origins: ["https://app.supaexplorer.com"],
  linkPath: "/extension/link",
  managePath: "/extension",
  api: {
    extensionLinks: "/api/extension-links",
  },
  pollIntervalMs: 4000,
  pendingTimeoutMs: 5 * 60 * 1000,
};
