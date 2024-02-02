export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.[jt]sx?$': ['ts-jest', { babelConfig: true }]
  },
  testPathIgnorePatterns: ["/node_modules/", "/dist/"],
  setupFilesAfterEnv: ["<rootDir>/tests/setupTests.ts"],
  transformIgnorePatterns: ["<rootDir>/node_modules/.pnpm/superjson@2.2.1/"],
};
