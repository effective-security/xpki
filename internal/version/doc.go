// Package version exposes the build version of the binaries. The version is
// set by the linker (-X ...internal/version.build=<version>, as make build
// does with GIT_VERSION) and otherwise read from the module build
// information, so a plain go build or go install reports its module version
// or VCS revision. PopulateFromBuild parses "[v]major.minor.commit[-dirty]".
package version
