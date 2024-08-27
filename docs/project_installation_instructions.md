## Installation

### Running a local installation for development

Running a local installation is recommended if:

- you use a Linux distribution
- you (and your team) use Windows exclusively (without WSL) AND do not use a Docker-based deployment.
- you don't have platform-specific dependencies

If this does not apply to you, move on to [Running a docker-based installation](#running-a-docker-based-installation-for-development).

Run
```shell
task initialise-project
```
to install a Poetry virtual environment, register the virtual environment as jupyter kernel, and install `pre-commit`. Pre-commit will automatically apply the Black code styler and clear notebook output upon committing files. If these actions change your file, you will have to add these changes to your commit as well.

If you receive errors about not having a valid python base version, create a new conda environment with the necessary python version and run the following
```shell
poetry env use ~/anaconda3/envs/<your_new_base_python_env>
task poetry
task initialise-project
```

*Note: If you use Pycharm, do not start PyCharm before running this command.* Otherwise it will not automatically detect your virtual environment and you will have to manually select it. If you have to this manually, you will have to point it to the `<repo_root>/.venv/bin/python` executable.



### Running a WSL 2-based installation

If you are using WSL, it is advised to clone your project within the WSL environment and connect to it with your IDE.

Ensure that the prerequisites are met within your WSL distribution.



### Running a docker-based installation for development

Running a docker-based installation is recommended if:

- You use Windows, but:

	- Do not use WSL
	- Plan to deploy your project in a Docker-based environment
	- Collaborate with Linux users

#### Preparation

Building Docker image

#### Configuring Pycharm

Use accompanying [/docker/dev-docker-compose.yml](/docker/dev-docker-compose.yml) file to allow setting of environment variables.

#### Configuring VS Code

This section should be written by someone who uses VS Code



### Selecting poetry virtual env in Pycharm:
Pycharm should automatically detect the new poetry virtual environment. If it doesn't, you will have to locate it manually.

You can do this as follows: `File -> Settings -> Project: <your project name> -> Python Interpreter -> Click on the cog-wheel icon -> Add .. -> Virtual Environment -> Existing Environment -> click the 'three-dot icon' -> locate your virtual environment in **<repo root>/.venv/bin/python**`

## Jupyter

If you executed the `task initialise-project` command, you should be ready to use the new virtual environment as a kernel with the name `nicegui_azure_entra_auth` in Jupyter. If not, continue reading.

To use Poetry's virtual environment in Jupyter notebooks, execute the following command:
```shell
task register-jupyter-kernel
```

Your virtual environment should then be available as a kernel in Jupyter with the name `nicegui_azure_entra_auth`.


### Using your project's code in your notebook

Make a copy of the provided template notebook, found in [/notebooks/notebook_template.ipynb](/notebooks/notebook_template.ipynb), whenever you need a new notebook. This template already contains some helpful cells to get you started and it already has the correct jupyter kernel for your project's Poetry virtual environment selected.

### Configuring (private) artifact repositories

For more information on how to configure your (private) artifact repository to install packages from or to upload packages to, refer to [/docs/configuring_private_artifact_repositories.md](/docs/configuring_private_artifact_repositories.md).
