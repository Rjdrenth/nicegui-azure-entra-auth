

# NiceGUI application with Azure Entra authentication

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![pi-project-template](https://img.shields.io/badge/π__project__template-1.0.2-green)](https://github.com/Rjdrenth/pi-project-template)
![coverage report](assets/images/coverage.svg)


This repository shows an example how you could build a NiceGUI web application and use Azure Entra to authenticate your microsoft users.

When I tried deploying my NiceGUI webapp as an Azure Web App I found that adding Entra authentication as an identity provider as a plug-and-play
solution to an Azure Web App did not work, as it blocked NiceGUI's websocket communication. This meant I had to resort to adding the authentication
flow to the application myself. No doubt this method, the method I came up with, is not the best method. I am open to suggestions and improving it.  

This is not a full-fledged repository with proper documentation, it is a bare-minimum effort to hopefully help someone else achieve the same.
Nevertheless, provided you jumped through all the regular hoops to register an application in Entra and provided the necessary values in the
[/.env](/.env.template) file, the example application is functional.

The example application itself can be found at [/nicegui_azure_entra_auth/minimal_nicegui_entra_auth_example.py](nicegui_azure_entra_auth/minimal_nicegui_entra_auth_example.py).


## Project tools & prerequisities

If youwant to run the example, read the following information.

For a detailed description of the tools that this project provides, read [/docs/project_tools.md](/docs/project_tools.md).

Installation instructions for these tools and other prerequisites can be found at [/docs/prerequisites_installation_instructions.md](/docs/prerequisites_installation_instructions.md).

## Initialise your project

Simply run `task initialise-project` to get started. For some more information regarding installation instructions, downloading data and using jupiter, please refer to [/docs/project_installation_instructions.md](/docs/project_installation_instructions.md).

<!---
It is advised to not adjust the text above, in order to make it easier to update this file when the project is updated according to the latest version of the project template.

Write your project-specific readme information below this comment. After updating, the previous text will be gone.
However, simply discard the Hunk deleting your text and it will be back.
-->

### Configuration

Be sure to:

- replace the default values where necessary in the [/nicegui_azure_entra_auth.env](nicegui_azure_entra_auth.env) file.

