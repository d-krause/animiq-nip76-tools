const webpack = require("webpack");
const path = require("path");
const fs = require('fs');
const { DuplicatesPlugin } = require("inspectpack/plugin");
const srcPackageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));

const isProduction = process.env.NODE_ENV == "production";


const distPackageJson = JSON.stringify(
  {
    "name": srcPackageJson.name,
    "version": srcPackageJson.version,
    "description": srcPackageJson.description,
    "author": srcPackageJson.author,
    "license": srcPackageJson.license,
    "repository": srcPackageJson.repository,
    "main": "bundle.js",
    "module": "bundle.js",
    "typings": "src/index.d.ts",
    "sideEffects": false
  }, null, '\t'
);
fs.writeFileSync(`${__dirname}/dist/package.json`, distPackageJson, 'utf8');
fs.writeFileSync(`${__dirname}/dist/README.md`, distPackageJson, 'utf8');

const config = {
  mode: 'development',
  devtool: 'inline-source-map',
  entry: "./src/index.ts",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "bundle.js",
    library: {
      type: "module",
    },
  },
  experiments: {
    outputModule: true,
  },
  plugins: [
    new DuplicatesPlugin({
      emitErrors: false,
      emitHandler: undefined,
      ignoredPackages: undefined,
      verbose: false
    }),
    new webpack.ProvidePlugin({
      // 'Buffer': ['buffer', 'Buffer'],
    }),
  ],
  module: {
    rules: [
      {
        test: /\.(ts|tsx)$/i,
        loader: "ts-loader",
        exclude: ["/node_modules/"],
      },
      {
        test: /\.(eot|svg|ttf|woff|woff2|png|jpg|gif)$/i,
        type: "asset",
      },
    ],
  },
  resolve: {
    extensions: [".tsx", ".ts", ".jsx", ".js", "..."],
    fallback: {
      // zlib: require.resolve('browserify-zlib'),
      // buffer: require.resolve('buffer'),
      // stream: require.resolve('stream-browserify'),
      // crypto: require.resolve('crypto-browserify'),
    },
    alias: {
      '@noble/hashes': path.join(__dirname, 'node_modules/@noble/hashes'),
    }
  }
};

module.exports = () => {
  if (isProduction) {
    config.mode = "production";
  } else {
    config.mode = "development";
  }
  return config;
};
