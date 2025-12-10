# Testing Policy and Jenkins CI

This document describes the automated testing policy for Secure File Vault and the Jenkins CI configuration included in the repository. It explains how to run tests locally, how the provided Jenkins job is configured, what environment variables and files are required, and the expectations for test quality.

## Purpose & Scope

- **Purpose:** Ensure code correctness, detect regressions early, and enforce basic quality gates before merging.
- **Scope:** Unit tests and project-level integration tests stored in the `tests/` folder and executed by `pytest` both locally and in CI.

## Test Types

- **Unit tests:** Fast, isolated tests covering functions in `key_management.py` and other modules. Located in `tests/` and run with `pytest`.
- **Integration / repository-level tests:** Tests that exercise multiple components together and may read/write small files under the workspace; they also run under the CI job.

## Where Tests Live

- Primary test folder: `tests/`
- Example test file: `tests/test_key_management.py` — exercises salt generation, key derivation, password policy, and salt persistence.

## Running Tests Locally

1. Create and activate a Python virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install project test/runtime dependencies:

```bash
pip install -r requirements.txt
# optionally: pip install coverage
```

3. Run the test suite with verbose output:

```bash
python -m pytest tests -v
```

4. Run an individual test file or test function, for example:

```bash
python -m pytest tests/test_key_management.py::test_password_policy -q
```

Notes:
- Tests may create small temporary files (the tests clean up after themselves where applicable).
- If a test touches the working directory, run tests from the repository root to ensure correct relative paths.

## Jenkins CI – Overview

This repository includes a Docker-based Jenkins service definition and job configuration to run tests automatically:

- Docker compose configuration: `docker-compose.yml` (service `jenkins`).
- Jenkins Dockerfile: `Dockerfile.jenkins` (used by the compose service).
- Pre-configured job: `jenkins/jobs/run_tests/config.xml` (job name: `run-tests`).
- Initialization scripts: `jenkins/init.groovy.d/create-job.groovy` and `create-user.groovy`.

The compose setup mounts the repository into Jenkins at `/var/jenkins_home/repo` so tests run against the repository contents.

## How the Jenkins Job Runs Tests

- Job name: `run-tests` (configuration present at `jenkins/jobs/run_tests/config.xml`).
- Builder command executed by the job:

```sh
cd "$WORKSPACE" || exit 1
# Run tests from the mounted repository to ensure the `tests/` folder is available
python -m pytest "$JENKINS_HOME"/repo/tests -v
```

Notes:
- The job runs `pytest` against the repository mounted into Jenkins at `/var/jenkins_home/repo` (the compose file sets this mount).
- Job and init scripts are provided so a fresh Jenkins container can create the `run-tests` job and an initial user automatically.

## Jenkins Docker Compose & Environment

- The `docker-compose.yml` binds:
	- `./jenkins/init.groovy.d` → `/var/jenkins_home/init.groovy.d` (initialization scripts)
	- `./jenkins/jobs` → `/var/jenkins_home/jobs` (job config)
	- `./` → `/var/jenkins_home/repo:ro` (read-only copy of the repository for test execution)
- Ports exposed by the compose service: host `8070` → container `8080` (Jenkins UI).
- The init script `create-user.groovy` reads environment variables `USER`, `PASSWORD`, and `FULLNAME` when Jenkins starts.

To bring up Jenkins (from the project root):

```bash
# ensure a .env file exists with USER, PASSWORD, FULLNAME (or set env vars directly)
docker compose up --build
```

Tips:
- If you use `docker-compose` (classic), the service name is `jenkins` in `docker-compose.yml` and the same commands apply.
- The job expects a working Python interpreter inside the Jenkins environment. The provided `Dockerfile.jenkins` should install Python and the project requirements.

## Credentials & Secrets

- `create-user.groovy` uses these environment variables: `USER`, `PASSWORD`, `FULLNAME`. Provide them via a `.env` file or your environment when starting the container.
- Do not commit `.env` files containing plaintext credentials. Keep secrets out of the repo.

## Test Failure Policy (CI)

- Any failing test in the Jenkins `run-tests` job indicates a failing build and should block merges until fixed.
- The job currently only runs tests; extend it to publish results, fail PR checks, or post notifications as needed.

## Troubleshooting

- If Jenkins cannot find `tests/`, confirm the repository is mounted into the container at `/var/jenkins_home/repo` and that the job references `"$JENKINS_HOME"/repo/tests`.
- If Python is missing inside the Jenkins container, check `Dockerfile.jenkins` and ensure `pip install -r requirements.txt` is executed or add the install step to the job commands.
- For permission errors on mounted volumes, verify the `user` mapping in `docker-compose.yml` matches your host user (the compose file sets `user: \"1000:1000\"`).

## Quick Reference — Commands

```bash
# Run tests locally
python -m pytest tests -v

# Bring up Jenkins (in project root; set .env with USER/PASSWORD/FULLNAME)
docker compose up --build

# Run a single test
python -m pytest tests/test_key_management.py -q
```

## Where to Look In This Repo

- Jenkins config: `jenkins/jobs/run_tests/config.xml`
- Jenkins init scripts: `jenkins/init.groovy.d/` (job + user creation)
- Docker compose: `docker-compose.yml`
- Tests: `tests/` (example tests in `tests/test_key_management.py`)

End of document.
