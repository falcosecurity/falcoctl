package process

// Installer is used to create or install a process in Kubernetes, or locally for the user
type Installer interface {
	Install() (err error)
}

// GetterOptions is a generic options interface that is used to send data to various processes
type GetterOptions interface {

	// Name returns a unique name to use for lookups
	Name() (name string)
}

// Process is a generic interface that represents one of the processes in Falcoctl
type Process interface {

	// Name returns a unique name to use for lookups
	Name() (name string)
}

// Getter is used to request a process from some persistent storage, either in Kubernetes
// or locally.
type Getter interface {

	// Get is the main method to fetch a process
	Get(opions GetterOptions) (newProcess Process, err error)
}

// Updater is used to update an existing process with new configuration. Update
// is idempotent and always accepts the most recent process sent to it as truth.
type Updater interface {

	// Update is the main method used to update an existing process. It accepts new configuration
	// and returns an updated object that is a merged object of the new configuration and existing
	// configuration.
	Update(process Process) (updatedProcess Process, err error)
}

// Remover is used to remove a process that has previously been installed
type Remover interface {

	// Remove a process from a persistent store
	Remove(process Process) (err error)
}
