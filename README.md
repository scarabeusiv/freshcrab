# freshcrab

Automatic updater and validator for openSUSE Tumbleweed/Factory — the updater crab, paired with rpmcrab (the linter crab). It watches upstream releases, queues updates for packages that are behind on Factory, and — via an agent — branches the package from its devel project, bumps the version, cleans the spec, builds it in OBS, validates it, and submits the update to the devel project.
