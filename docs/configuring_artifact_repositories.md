
# Configuring (private) artifact repositories

Before publishing your package, don't forget to increase its version! Use one of the following commands to do so:
```shell
task bump-version-major  # Increases the X in x.y.z
task bump-version-minor  # Increases the Y in x.y.z
task bump-version-patch  # Increases the Z in x.y.z
```

## Publishing packages to Pypi

In order to publish to Pypi.org, either:

- add the relevant credentials to [/nicegui_azure_entra_auth.env](/nicegui_azure_entra_auth.env)
- specify an extra `.env` file that contains the credentials

You can then use the command below to publish your package to Pypi:
```shell
task publish-package-pypi
```

## Google Artifact Registry

A robust method of authenticating with Google Artifact Registry, is to download a Service Account's key. To obtain such a key, follow the instructions at [this google documentation page](https://cloud.google.com/artifact-registry/docs/python/authentication#sa-key).

If you are using this method, then the value of `GCP_ARTIFACT_USER` will be `_json_key_base64` and the valye of `GCP_ARTIFACT_PASSWORD` will be a long-ass string. These values should be used in the commands below and/or set in the [/nicegui_azure_entra_auth.env](/nicegui_azure_entra_auth.env) file.

### Installing from Google Artifact Registry

If you're using a private Google Artifact Registry, be sure to add the following snippet to [pyproject.toml](/pyproject.toml), e.g. directly after the dependency specifications.
Be sure to replace `<GCP_ARTIFACT_URL>` with the correct URL.

```
[[tool.poetry.source]]
name = "google_artifact"
url = "<GCP_ARTIFACT_URL>"
```

You will also need to execute the commands below, where the variables should either be loaded (sourced) into your shell or replaced with their corresponding values before executing the commands:
```shell
poetry config repositories.google_artifact $GCP_ARTIFACT_URL
poetry config http-basic.google_artifact $GCP_ARTIFACT_USER $GCP_ARTIFACT_PASSWORD
```

You should then be able to install your private package using `poetry add <package_name>` like you would install any public packages.

### Publishing packages to Google Artifacts
In order to publish to Google Artifacts, either:

- add the relevant credentials to [/nicegui_azure_entra_auth.env](/nicegui_azure_entra_auth.env)
- specify an extra `.env` file that contains the credentials

You can then use the command below to publish your package to Google Artifacts:
```shell
task publish-package-google-artifacts
```

### Installing packages from Google Artifacts in Docker
If you're building a Docker image that needs access to Google Artifact Registry, you need to:

- Ensure authentication to Google Artifact is setup by either:
  - Adding the relevant credentials to [/nicegui_azure_entra_auth.env](/nicegui_azure_entra_auth.env)
  - Specifying an extra `.env` file that contains the credentials

- Uncomment the relevant commented parts in the Dockerfiles in [/docker](/docker)
- Change the build tasks located in [/taskfiles/docker_tasks.yml](/taskfiles/docker_tasks.yml), and the various versions of this file, to use the relevant commented lines instead of the default line.

After doing this, you can execute one of the tasks to build a docker image, e.g.
```shell
task docker:build
```
