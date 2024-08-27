# π Python Project Template - Prerequisites

## Prerequisites

This project requires the following software to be installed on your system:

- Python 3.10 or higher

- [git](https://git-scm.com/download/win)

  - On Windows it is assumed that this also install `sh.exe`, which is bundled with git.

- [Poetry](https://python-poetry.org/) for virtual environment management.

  - See [Poetry's installation instructions](https://python-poetry.org/docs/#installation) webpage.

- [go-task](https://taskfile.dev/) - a cross-platform task runner (a Make alternative)

  - Check [this page](https://taskfile.dev/installation) for installation instructions:

    - Ubuntu TLDR: run `sudo snap install task --classic`
    - WSL TLDR: run `sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin`
    - Windows TLDR: go to [the github releases page](https://github.com/go-task/task/releases) and don't forget to click `show all assets`.

  - Check https://github.com/go-task/task/pull/906 and https://github.com/go-task/task/tree/master/completion regarding command completion in your shell.

- [Docker](https://docs.docker.com/engine/install/) - Optional


## Python

If your OS already ships with python, you don't have to do much. If this is not the case, or if you wish to upgrade your version or install multiple python versions, [Anaconda](https://docs.anaconda.com/anaconda/install/) is recommended to manage the python versions installed on your system.


## Git

### Windows

Windows users should visit [git's webpage](https://git-scm.com/download/win). It is assumed that using this installer also install `sh.exe`, which comes bundled with git.

### Linux

Installing git is simple as running

```shell
sudo apt get install git
```

## Cookiecutter installation

Simply run

```shell
pip install cookiecutter
```

## Poetry installation

See [Poetry's installation instructions](https://python-poetry.org/docs/#installation) webpage.

## Task installation instructions

Check [this page](https://taskfile.dev/installation) for installation instructions:

- Ubuntu TLDR: run `sudo snap install task --classic`
- WSL / Docker TLDR: run `sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin`
- Windows TLDR: go to [the github releases page](https://github.com/go-task/task/releases) and don't forget to click `show all assets`.

Command completion in various shells is also availabe. Check https://github.com/go-task/task/pull/906 and https://github.com/go-task/task/tree/master/completion regarding command completion in your shell.
