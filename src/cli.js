#!/usr/bin/env node

const [, , command] = process.argv;

if (command === "setup") {
  console.log("http-native: setting up native binary...");
  // TODO: download or build the platform-specific .node binary
  console.log("http-native: done.");
} else {
  console.log(`Usage: http-native setup`);
}
