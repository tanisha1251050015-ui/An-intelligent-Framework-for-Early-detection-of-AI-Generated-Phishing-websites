/**
 * Manifest V3 validation for the PIP Inspector extension.
 *
 * Run with: npm test  (or: node tests/validate_manifest.js)
 */

const fs = require("node:fs");
const path = require("node:path");

const manifestPath = path.join(__dirname, "..", "manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

const failures = [];

function check(condition, message) {
  if (!condition) failures.push(message);
}

check(manifest.manifest_version === 3, "manifest_version must be 3");
check(typeof manifest.name === "string" && manifest.name.length > 0, "name is required");
check(
  /^\d+\.\d+\.\d+$/.test(manifest.version),
  `version must be semver, got: ${manifest.version}`,
);
check(typeof manifest.description === "string", "description is required");
check(
  manifest.background && typeof manifest.background.service_worker === "string",
  "background.service_worker is required",
);
check(
  manifest.action && typeof manifest.action.default_popup === "string",
  "action.default_popup is required",
);
check(
  Array.isArray(manifest.permissions),
  "permissions must be an array",
);
check(
  manifest.permissions.includes("storage"),
  "storage permission is required",
);
check(
  manifest.permissions.includes("activeTab"),
  "activeTab permission is required for current-tab inspection",
);
check(
  Array.isArray(manifest.host_permissions) &&
    manifest.host_permissions.includes("http://localhost:8000/*"),
  "host_permissions must include the PIP backend origin",
);
check(
  Array.isArray(manifest.content_scripts) &&
    manifest.content_scripts.every(
      (cs) => Array.isArray(cs.matches) && Array.isArray(cs.js),
    ),
  "content_scripts must declare matches and js",
);

if (failures.length > 0) {
  console.error("Manifest validation failed:");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(`Manifest OK: ${manifest.name} v${manifest.version} (MV3)`);
