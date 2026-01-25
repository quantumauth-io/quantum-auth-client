package buildinfo

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	// e.g. "v0.3.1 (abc1234, 2026-01-21)"
	v := Version
	if len(Commit) > 7 {
		Commit = Commit[:7]
	}
	return v + " (" + Commit + ", " + Date + ")"
}
