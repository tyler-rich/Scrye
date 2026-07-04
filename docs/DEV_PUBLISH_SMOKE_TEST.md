# :dev publish smoke test

Throwaway marker file used to verify that merging a pull request into `dev`
triggers the `Publish` workflow's `dev` job and pushes `securedbytyler/scrye:dev`
to Docker Hub (`.github/workflows/publish.yml`).

Safe to delete once the `:dev` publish run has been confirmed.
