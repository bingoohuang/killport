<div align="center">
<a href="https://github.com/jkfran/jkfran.com/stargazers"><img src="https://img.shields.io/github/stars/jkfran/killport" alt="Stars Badge"/></a>
<a href="https://github.com/jkfran/jkfran.com/network/members"><img src="https://img.shields.io/github/forks/jkfran/killport" alt="Forks Badge"/></a>
<a href="https://github.com/jkfran/jkfran.com/pulls"><img src="https://img.shields.io/github/issues-pr/jkfran/killport" alt="Pull Requests Badge"/></a>
<a href="https://github.com/jkfran/jkfran.com/issues"><img src="https://img.shields.io/github/issues/jkfran/killport" alt="Issues Badge"/></a>
<a href="https://github.com/jkfran/jkfran.com/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/jkfran/killport?color=2b9348"></a>
<a href="https://github.com/jkfran/jkfran.com/blob/master/LICENSE"><img src="https://img.shields.io/github/license/jkfran/killport?color=2b9348" alt="License Badge"/></a>
</div>
<br>

# killport

`killport` is a command-line utility for killing processes listening on specific ports. It's designed to be simple, fast, and effective. The tool is built with Rust and works on Linux, macOS, and Windows.

## Features

- Kill processes by port number
- Supports multiple port numbers
- Verbosity control
- Works on Linux, macOS and Windows

## Installation

### Using Homebrew

Run the following command to install killport using Homebrew.

```sh
brew tap jkfran/killport
brew install killport
```

### Using install.sh

Run the following command to automatically download and install `killport`:

```sh
curl -sL https://bit.ly/killport | sh
```

Don't forget to add `$HOME/.local/bin` to your `PATH` environment variable, if it's not already present.

### Using cargo

Run the following command to install killport using cargo. If you don't have cargo, follow the [official Rust installation guide](https://www.rust-lang.org/tools/install).

```sh
cargo install killport
```

### Binary Releases

You can download the binary releases for different architectures from the [releases page](https://github.com/jkfran/killport/releases) and manually install them.

## Usage

```sh
killport [FLAGS] <ports>...
```

### Examples

Kill a single process listening on port 8080:

```sh
killport 8080
```

Kill multiple processes listening on ports 8045, 8046, and 8080:

```sh
killport 8045 8046 8080
```

Kill processes with specified signal:

```sh
killport -s sigkill 8080
```

### Flags

```shell
Usage: killport [OPTIONS] <ports>...

Arguments:
  <ports>...  The list of port numbers to kill processes on

Options:
  -x, --execute       Execute the kill or only show the target processes
  -s, --signal <SIG>  SIG is a signal name [default: sigterm] [possible values: sigkill, sigterm]
  -v, --verbose...    More output per occurrence
  -q, --quiet...      Less output per occurrence
  -h, --help          Print help
  -V, --version       Print version
```

## Contributing

We welcome contributions to the killport project! Before you start, please read our [Code of Conduct](CODE_OF_CONDUCT.md) and the [Contributing Guidelines](CONTRIBUTING.md).

To contribute, follow these steps:

1. Fork the repository on GitHub.
2. Clone your fork and create a new branch for your feature or bugfix.
3. Make your changes, following our coding guidelines.
4. Add tests for your changes and ensure all tests pass.
5. Commit your changes, following our commit message guidelines.
6. Push your changes to your fork and create a pull request.

We'll review your pull request and provide feedback or merge your changes.

## License

This project is licensed under the [MIT License](LICENSE). See the LICENSE file for more information.

