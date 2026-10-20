//go:build !windows

package managedsession

func validateLocalPath(path string) error { return checkLocalParents(path) }
