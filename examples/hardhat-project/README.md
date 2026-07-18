# ChainProof Hardhat Example

Example Hardhat project demonstrating `@chainproof/hardhat-plugin`.

## Setup

From the repository root:

```bash
npm install
npm run build
cd examples/hardhat-project
npm install
```

## Tasks

```bash
# Full audit
npx hardhat chainproof

# Fast CI check (exit code 1 on critical/high)
npx hardhat chainproof:check

# Generate report file
npx hardhat chainproof:report --format markdown --output audit.md
```

## Compile hook

Enable automatic scans after compile in `hardhat.config.ts`:

```typescript
chainproof: {
  runOnCompile: true,
  failOnCompile: false,
}
```

Then run `npx hardhat compile`.

## Test footer

When running tests on the Hardhat Network (`npx hardhat test`), ChainProof prints a security summary footer after test output.
