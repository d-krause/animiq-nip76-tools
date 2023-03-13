module.exports = {
  testEnvironment: "jsdom",
  setupFilesAfterEnv: ['./test/env.ts'],
  preset: 'ts-jest',
  transform: {
    '^.+spec\\.(ts|tsx)?$': 'ts-jest',
    //   "^.+\\.(js|jsx)$": "babel-jest",
  }
};