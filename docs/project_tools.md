# π Python Project Template - Features

## Poetry

Poetry is used to manage your project's dependencies and virtual environment. I refer to Poetry's [excellent documentation](https://python-poetry.org/docs/basic-usage/) for more information regarding its usage.

## Pre-commit

[Pre-commit](https://pre-commit.com/) is a tool that runs a set of tasks right before a commit is made. The provided configuration, located in [.pre-commit-config.yaml](/nicegui_azure_entra_auth/.pre-commit-config.yaml), has the following features:

Features:

- Code formatting with [Black](https://github.com/psf/black)
- Import sorting with [isort](https://pycqa.github.io/isort/)
- Clear notebook output. Remove the hook with id `jupyter-notebook-cleanup` to disable.
- Remove Trailing whitespace (except Markdown). Remove the hook with id `trailing-whitespace` to disable.
- Prevent large files from being committed. Remove the hook with id `check-added-large-files` to disable.
- Enforce [Black] code guidelines. Remove the hook with id `black` to disable.

  - Change settings in the `[tool.black]` section in [pyproject.toml](/pyproject.toml), such as line length.

## Jupyter Notebook template

The Jupyter notebook template features the following:

- Automatically reloads packages for which the code has changed, such as your own code.
- Selects the appropriate kernel for your project's virtual environment
- Code formatting with [Black](https://github.com/psf/black)

## Task

[Task](https://taskfile.dev) is a cross-platform task runner and can be used to provide command-line shorthands for various project-related tasks that are performed often or as a shorthand for long commands. It is an alternative to [Make](https://www.gnu.org/software/make/), which was designed for Unix platforms.

The [Taskfile.yml](/Taskfile.yml) file contains the configuration for various commands to help you manage your project and can be extended with what is relevant for your project.

Every task can be called by typing `task <task_name>` within your repository root. Typing `task` displays the available commands:

```
task: Available tasks for this project:
* bump-version-major:       Increases the major version of your project according to semantic versioning. In "x.y.z" the "x" is increased.
* bump-version-minor:       Increases the minor version of your project according to semantic versioning. In "x.y.z" the "y" is increased.
* bump-version-patch:       Increases the patch version of your project according to semantic versioning. In "x.y.z" the "z" is increased.
* coverage:                 Calculate test coverage
* docker:build:             Build a Docker image to run/deploy your project.
* docker:inspect:           Start a container and open a shell to inspect its contents and execute commands.
* docker:run:               Start a container using your project's Docker image.
* docker:test:              Execute your project's tests in a Docker container.
* initialise-project:
    Initialises your project by:
     1) creating the poetry virtual environment
     2) Installing pre-commit
     3) Registering the virtual environment as jupyter kernel
* poetry:                                Update poetry and create / update your virtual environment.
* pre-commit-all:                        Apply pre-commit to all files.
* pre-commit-install:                    Install pre-commit for your repository so it runs after each commit.
* pre-commit-uninstall:                  Uninstall pre-commit for your repository so it no longer runs after each commit.
* publish-package-google-artifacts       Upload nicegui_azure_entra_auth to Google Artifact Registry
* publish-package-pypi:                  Upload nicegui_azure_entra_auth to PyPI
* pytest:                                Execute all tests.
* reset-venv:                            Deletes and reinitialises your virtual environment.
```

## Bump2version

The bump2version config file will be located at [/.bumpversion.cfg](/.bumpversion.cfg) in your new project. It defines various places where the version of your project is located. Extend it if neccesary.

## Docker

The [/docker](/docker) folder contains multiple Dockerfiles, each with their own purpose:

- [Dockerfile](/docker/Dockerfile) - Your basic Dockerfile for a basic Docker-based deployment. It installs the project and all dependencies as a non-root user and calls the script at [/nicegui_azure_entra_auth/scripts/deployment/container_entry_point.py](/nicegui_azure_entra_auth/scripts/deployment/container_entry_point.py) when the container starts.

- [venv_Dockerfile](/docker/venv_Dockerfile) - A Dockerfile that is very much the same as the basic Dockerfile with a few key differences:

  - Development dependencies are also installed, as this image is meant to be used for development
  - It starts a Jupyter server instead of executing the `container_entry_point.py` script.
  - Your project's code is not copied to the image. Instead, your project root is mounted when a container is started (using the corresponding `task docker_venv:run` command)

  - To use the corresponding `task` commands, you will need to uncommend the line `# docker_venv: Taskfiles/docker_venv_tasks.yml` in the `include` section of the [Taskfile.yml](/Taskfile.yml).


- [pypy_Dockerfile](/docker/pypy_Dockerfile) - Your basic Pypy Dockerfile for a basic Docker-based deployment. It installs the project and all dependencies as a non-root user and calls the script at [/nicegui_azure_entra_auth/scripts/deployment/container_entry_point.py](/nicegui_azure_entra_auth/scripts/deployment/container_entry_point.py) when the container starts.

  - To use the corresponding `task` commands, you will need to uncommend the line `# docker_pypy: Taskfiles/docker_pypy_tasks.yml` in the `include` section of the [Taskfile.yml](/Taskfile.yml).

  - There are a few key differences between this `pypy_Dockerfile` and the regular `Dockerfile`:

    - It uses a [Pypy](https://www.pypy.org/)-based Docker image, meaning it uses the faster Pypy interpreter (compared to the regular CPython interpreter). Note that when choosing this interpreter, Pypy behaves slightly different from Cpython in a few cases - see [this page](https://doc.pypy.org/en/latest/cpython_differences.html) for information. Honestly, this most likely will not affect you, but if it does, you know this might be the cause.

    - The Python versions supported by Pypy always slightly lag behind the regular Python versions. The latest Python version supported by Pypy is `3.9.7`. As such, the `pypy_Dockerfile` does not adhere to the minimum python version that was specified in its selection of a base image, but pins it to the latest patch-version of Python `3.9`.

## Publishing packages

This project template also supports publishing your package to public and private repositories.

### Publishing to PyPI

To publish your package to PyPI, you need to:

- Have a PyPI account.
- Set your PyPI username and password in your project's [/nicegui_azure_entra_auth.env](/nicegui_azure_entra_auth.env) file.
- Increase your package's version number using the `task bump-version-patch`, `task bump-version-minor` or `task bump-version-major` commands.
- Actually publish it with the `task publish-package-pypi` command.

### Publishing to Google Artifact Registry
To publish your package to Google Artifact Registry, you need to:

- Have access to a Artifact Registry.
- Follow the instructions in [/docs/configuring_artifact_repositories.md](/docs/configuring_artifact_repositories.md) to configure your environment.
- Increase your package's version number using the `task bump-version-patch`, `task bump-version-minor` or `task bump-version-major` commands.
- Actually publish it with the `task publish-package-google-artifacts` command.
