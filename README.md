# govulners-db

Application to create a govulners vulnerability database from upstream vulnerability data sources.

## Installation

**Note**: Currently, Govulners-DB is built only for Linux and macOS.

### Recommended

```bash
curl -sSfL https://raw.githubusercontent.com/nextlinux/govulners-db/main/install.sh | sh -s -- -b /usr/local/bin
```

... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/nextlinux/govulners-db/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

## Usage

To pull the vulnerability source data, build the `vulnerability.db` file, and package the database into a `tar.gz` run the following:

```bash
govulners-db [-g] [--dir=DIR] [--schema=SCHEMA] [--skip-validation] [--publish-base-url=URL] [-p PROVIDER ...]
```

Or you can choose to run these steps individually:

```bash
# Pull all upstream vulnerability data sources to local cache
govulners-db pull [-g] [-p PROVIDER ...]

# Build a SQLite DB from the vulnerability data for a particular schema version
govulners-db build [-g] [--dir=DIR] [--schema=SCHEMA] [--skip-validation] [-p PROVIDER ...]

# Package the already built DB file into an archive ready for upload and serving
govulners-db package [--dir=DIR] [--publish-base-url=URL]
```

The `pull` command downloads and caches vulnerability data from upstream sources (e.g. NIST, redhat, github, canonical, etc.) into
a cache directory. The cache location is a platform dependent XDG directory, however, the location can be overridden with the `cache.dir`
configuration option. The default configuration is to use [vunnel](https://github.com/nextlinux/vunnel) to fetch and
process the vulnerability data. Use `-g` to generate the list of providers to pull based on the output of "vunnel list".

**note: you can skip the `pull` step if you already have a local cache of vulnerability data (with `make download-all-provider-cache`).**

The `build` command processes the cached vuln data generate a `vulnerability.db` sqlite3 file. Additionally, a `metadata.json`
is created that is used in packaging and curation of the database file by this application and downstream consuming applications.
Use `-g` to generate the list of providers to pull based on the output of "vunnel list".

The `package` command archives the `vulnerability.db` and `metadata.json` files into a `tar.gz` file. Additionally, a `listing.json`
is generated to aid in serving one or more database archives for downstream consumption, where the consuming application should
use the listing file to discover available archives available for download. The base URL used to create the download URL for each
database archive is controlled by the `package.base-url` configuration option.

You can additionally manage vulnerability data cache with the following commands:

```bash
# backup all cached vulnerability data or a specific PROVIDER to a tar.gz file (PATH)
govulners-db cache backup [--path=PATH] [--provider-name=PROVIDER]

# delete all cached vulnerability data or a specific PROVIDER
govulners-db cache delete [--provider-name=PROVIDER]

# restore vulnerability cache from a tar.gz file (PATH)
govulners-db cache restore [--path=PATH] [--delete-existing]

# show the current state of the all vulnerability data cache or a specific PROVIDER
govulners-db cache status [--provider-name=PROVIDER ...]
```

## DB Schemas

This repo supports building databases for all supported versions of govulners, even when the data shape has changed.
For every change in the data shape over time, a new schema is created (see the DEVELOPING.md for details on how to bump the schema).

**For every schema govulners-db supports, we build a DB for that schema nightly. To reduce nightly DB maintenance, try to keep the schema bumps to a minimum during development.**

Once a schema has been created, the previous schema should be considered locked unless making bug fixes or updates related to [vunnel](https://github.com/nextlinux/vunnel), or otherwise upstream data shape changes.

If the development being done requires any of the following, then a **new schema is required to be created** (over further developing the current schema):

- If a previous version of govulners using the same schema would not function with the new changes
- If the current version of govulners using a previously published database (but still the same schema) would not function with the new changes

Where "would not function" means either govulners will error out during processing, or the results are otherwise compromised (e.g. missing data that otherwise could/should have been found and reported).

The following kinds of changes **do not necessarily require a new schema**:

- Adding a new data source
- Removing an existing data source (as long as the govulners matchers are not requiring its presence)

There are plenty of grey areas between these cases (e.g. changing the expected set of values for a field, or changing the semantics for a column) --use your best judgement.

This repo is responsible for publishing DBs with the latest vulnerability data for every supported schema daily.
This is achieved with the [Daily Data Sync](https://github.com/nextlinux/govulners-db/actions/workflows/daily-data-sync.yaml) and [Daily DB Publisher](https://github.com/nextlinux/govulners-db/actions/workflows/daily-db-publisher.yaml) GitHub Actions workflows.
Which schemas are built and which govulners versions are used to verify functionality is controlled with the `govulners-schema-version-mapping.json` file in the root of this repo
(see the DEVELOPING.md for more details).

## Configuration

```yaml
# suppress all output
# same as -q ; GOVULNERS_DB_QUIET env var
quiet: false

log:
  # the log level; note: detailed logging suppress the ETUI
  # same as GOVULNERS_DB_LOG_LEVEL env var
  level: "error"

  # location to write the log file (default is not to have a log file)
  # same as GOVULNERS_DB_LOG_FILE env var
  file: ""

provider:
  # where to read and write all provider data. The state must be oriented as described 
  # in https://github.com/nextlinux/vunnel/tree/main/schema/provider-workspace-state .
  # Note: all location references under `providers` should be relative to this directory
  # same as GOVULNERS_DB_PROVIDER_ROOT env var
  root: ./data

  # names of providers to filter down to while running
  # same as -p
  include-filter: []
  
  vunnel:
    # how to execute vunnel. Options are:
    #  - "docker" (default): execute vunnel in a docker container
    #  - "local": execute vunnel on the host from what is in your $PATH
    executor: docker
    
    # the docker image to use when executing vunnel with executor=docker
    docker-tag: latest
    docker-image: ghcr.io/nextlinux/vunnel
    
    # generate additional provider configuration files based on the "vunnel list" command
    # same as -g ; GOVULNERS_DB_GENERATE_CONFIGS env var
    generate-configs: true
    
    # providers to exclude from the "vunnel list" command (only applies when generate-configs=true)
    exclude-providers:
      - centos
    
    # environment variables to set when executing vunnel
    env: {}
    
  # manually crafted provider configurations. (advanced use only)
  configs: []

pull:
  # the number of concurrent workers to use when pulling and processing data
  parallelism: 1

build:
  # where to place the built SQLite DB that is built from the "build" command
  # same as --dir; GOVULNERS_DB_BUILD_DIR env var
  dir: "./build"

  # the DB schema version to build
  # same as --schema-version; GOVULNERS_DB_BUILD_SCHEMA_VERSION env var
  schema-version: 5

  # skip validation of the provider state
  skip-validation: false

package:
  # this is the base URL that is referenced in the listing file created during the "package" command
  # same as GOVULNERS_DB_PACKAGE_PUBLISH_BASE_URL env var
  publish-base-url: "https://localhost:8080/govulners/databases"

  # limit the providers to pull based off of this list. (empty list means pull all providers)
  provider-names: []

```
