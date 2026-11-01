package checks

import "github.com/s0sta/nabd/internal/core"

// All is every check, in the order they are listed.
func All() []core.Check {
	return []core.Check{Disk, Memory, CPU, Services, Kernel, Time, Reboot, Packages, Network, Ports, SSH, Certs, Procs, Accounts}
}
