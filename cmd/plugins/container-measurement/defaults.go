package main

const (
	// DefaultRootDir is the default location used by containerd to store
	// persistent data
	DefaultRootDir = "/var/lib/containerd"
	// DefaultStateDir is the default location used by containerd to store
	// transient data
	DefaultStateDir = "/var/run/containerd"
	// DefaultAddress is the default unix socket address
	DefaultAddress = "/var/run/containerd/containerd.sock"
	// DefaultDebugAddress is the default unix socket address for pprof data
	DefaultDebugAddress = "/var/run/containerd/debug.sock"
	// DefaultFIFODir is the default location used by client-side cio library
	// to store FIFOs.
	DefaultFIFODir = "/var/run/containerd/fifo"
	// DefaultRuntime would be a multiple of choices, thus empty
	DefaultRuntime = ""
	// DefaultConfigDir is the default location for config files.
	DefaultConfigDir = "/etc/containerd"
)
