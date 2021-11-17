/** @type {import('ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
  preset: "jest-puppeteer",
  transform: {
    "^.+\\.ts?$": "ts-jest",
  },
};
