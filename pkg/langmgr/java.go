package langmgr

import (
	"context"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// javaManager handles patching of Java/JVM library updates reported by Trivy
// (jar, pom, gradle, sbt types - all mapped to packageurl.TypeMaven upstream).
//
// This is the foundation scaffold. The full patching strategy (download
// patched JARs from a Maven repository and replace each copy in the target
// image) is implemented in follow-up PRs tracked under the Java patching
// roadmap. See the tracking issue for the full series.
//
// In this scaffold InstallUpdates returns the original state unchanged and
// reports every Java update as a failed package, so users hitting Java vulns
// get a clear log message and the orchestrator routes them through
// --ignore-errors handling rather than silently skipping.
type javaManager struct {
	config        *buildkit.Config
	workingFolder string
}

// isJavaUpdate returns true when the package type is one of Trivy's Java
// language types. Used by both the manager and the report parser.
func isJavaUpdate(t string) bool {
	return t == utils.JavaJar || t == utils.JavaPom || t == utils.JavaGradle || t == utils.JavaSbt
}

// filterJavaUpdates returns the subset of language updates that target the
// Java ecosystem.
func filterJavaUpdates(updates unversioned.LangUpdatePackages) unversioned.LangUpdatePackages {
	var out unversioned.LangUpdatePackages
	for _, u := range updates {
		if isJavaUpdate(u.Type) {
			out = append(out, u)
		}
	}
	return out
}

// InstallUpdates is the LangManager entry point. The foundation scaffold logs
// each affected coordinate, returns the unchanged state, and reports the Java
// updates as failed packages so the caller can decide whether to hard-fail or
// continue under --ignore-errors.
func (jm *javaManager) InstallUpdates(
	_ context.Context,
	currentState *llb.State,
	manifest *unversioned.UpdateManifest,
	_ bool,
) (*llb.State, []string, error) {
	if manifest == nil || len(manifest.LangUpdates) == 0 {
		return currentState, nil, nil
	}

	javaUpdates := filterJavaUpdates(manifest.LangUpdates)
	if len(javaUpdates) == 0 {
		return currentState, nil, nil
	}

	log.Warnf("Java/JVM library patching is not yet implemented. %d update(s) skipped.", len(javaUpdates))
	failed := make([]string, 0, len(javaUpdates))
	for _, u := range javaUpdates {
		log.Debugf("  Java skipped: %s (installed=%s, fixed=%s, type=%s, path=%s)",
			u.Name, u.InstalledVersion, u.FixedVersion, u.Type, u.PkgPath)
		failed = append(failed, u.Name)
	}
	return currentState, failed, nil
}
