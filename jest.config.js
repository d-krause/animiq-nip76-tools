module.exports = {
  testEnvironment: "jsdom",
  preset: 'ts-jest',
  transform: {
    '^.+spec\\.(ts|tsx)?$': 'ts-jest',
    //   "^.+\\.(js|jsx)$": "babel-jest",
  }
};