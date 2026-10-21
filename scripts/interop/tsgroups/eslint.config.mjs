// The structural floor (macula-io/macula-codebase-checks#9): deep nesting and
// tangled functions fail the build. No baseline, no inline disables.
const floor = {
  "max-depth": ["error", 3],
  "complexity": ["error", 9],
};

export default [
  { ignores: ["node_modules/", "dist/", "out/"] },
  {
    files: ["**/*.mjs", "**/*.js"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: floor,
  },
];
