import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def _assert_no_changes():
    """
    Check whether there are no working changes in the repository.
    """
    lines = [
        line.strip()
        for line in subprocess.check_output(["git", "status", "--porcelain"]).splitlines()
        if not line.strip().startswith(b"??")
    ]

    if lines:
        logger.error(
            "Git working directory is not clean. Commit or stash your changes first.\nFiles with changes:\n{}".format(
                b"\n".join(lines).decode()
            )
        )

        sys.exit(1)


def _create_temp_project(repo_root, repo_parent_dir):
    """
    Create a new project using the cookiecutter template, with the same parameter as were used for the current project.
    """
    print("Creating temp project")

    completed_process = subprocess.run(
        [
            "cookiecutter",
            "--replay-file",
            str(repo_root / ".project_template" / "cookiecutter_replay.json"),
            "--output-dir",
            str(repo_parent_dir),
            "git+ssh://git@github.com/Rjdrenth/pi-project-template.git",
        ],
        capture_output=True,
        text=True,
        input="yes",
    )

    # Open cookiecutter_replay.json to determine where the temporary project will be created
    with open(repo_root / ".project_template" / "cookiecutter_replay.json", "r") as replay_file:
        original_replay = json.load(replay_file)

    # Read the cookiecutter_replay.json file from the temporary project
    temp_replay_file_path = (
        repo_parent_dir
        / original_replay["cookiecutter"]["project_repository_name"]
        / ".project_template"
        / "cookiecutter_replay.json"
    )
    with open(temp_replay_file_path, "r") as temp_replay_file:
        temp_replay = json.load(temp_replay_file)

    # Replace the occurence of `_temp_temp` with `_temp`
    temp_replay["cookiecutter"]["project_repository_name"] = temp_replay["cookiecutter"][
        "project_repository_name"
    ].replace("_temp_temp", "_temp")

    # And write it back to the cookiecutter_replay.json file of the temp project
    with open(temp_replay_file_path, "w") as temp_replay_file:
        json.dump(temp_replay, temp_replay_file, indent=4)

    print(completed_process)


def patch_file(repo_parent_dir, repo_root, temp_repo_root, file_to_update: Path):
    print(f"Updating {file_to_update}")

    # Create Path objects referencing to the file that is to be updated in both the actual repo and temporary repo.
    file_path_to_update = repo_parent_dir / Path(repo_root.name) / file_to_update
    potentially_updated_file = repo_parent_dir / Path(temp_repo_root.name) / file_to_update

    # Simply copy the file
    shutil.copy(potentially_updated_file, file_path_to_update)


if __name__ == "__main__":
    # Ensure there's no un-staged ior un-stashed changes in the git directory
    _assert_no_changes()

    # Create references to relevant directories
    current_file_path = Path(__file__).resolve()
    repo_parent_dir_ = current_file_path.parents[2]
    repo_root_ = current_file_path.parents[1]
    temp_repo_root_ = repo_parent_dir_ / f"{repo_root_.name}_temp"

    # Create a new project using the cookiecutter template, with the same parameter as were used for the current project
    _create_temp_project(repo_root_, repo_parent_dir_)

    # List of files that we want to patch
    files = [
        Path(".bumpversion.cfg"),
        Path(".pre-commit-config.yaml"),
        Path("Taskfile.yml"),
        Path("pyproject.toml"),
        Path("README.md"),
        Path(".project_template") / "cookiecutter_replay.json",
        Path(".project_template") / "project_template_metadata.json",
        Path(".project_template") / "update_project_template.py",
        Path("docs") / "configuring_artifact_repositories.md",
        Path("docs") / "prerequisites_installation_instructions.md",
        Path("docs") / "project_installation_instructions.md",
        Path("docs") / "project_tools.md",
        Path("docker") / "Dockerfile",
        Path("docker") / "pypy_Dockerfile",
        Path("docker") / "venv_Dockerfile",
        Path("Taskfiles") / "docker_tasks.yml",
        Path("Taskfiles") / "docker_pypy_tasks.yml",
        Path("Taskfiles") / "docker_venv_tasks.yml",
    ]

    # Path the files one by one
    print()
    for f in files:
        patch_file(repo_parent_dir_, repo_root_, temp_repo_root_, f)

    # Delete the temporary repository
    shutil.rmtree(temp_repo_root_)
