package securevault

import "time"

// Snapshot contains aggregate operational health and no archived data or secrets.
type Snapshot struct {
	Accepted       uint64     `json:"accepted"`
	Dropped        uint64     `json:"dropped"`
	QueueDepth     int        `json:"queue_depth"`
	SpoolPending   int64      `json:"spool_pending"`
	Quarantined    int64      `json:"quarantined"`
	LocalFailures  uint64     `json:"local_failures"`
	UploadFailures uint64     `json:"upload_failures"`
	Uploaded       uint64     `json:"uploaded"`
	LastUploadedAt *time.Time `json:"last_uploaded_at,omitempty"`
	LastFailureAt  *time.Time `json:"last_failure_at,omitempty"`
}

// Snapshot returns a non-blocking point-in-time view of the Vault workers.
func (v *Vault) Snapshot() Snapshot {
	if v == nil {
		return Snapshot{}
	}
	return Snapshot{
		Accepted: v.accepted.Load(), Dropped: v.dropped.Load(), QueueDepth: len(v.jobs),
		SpoolPending: v.spoolPending.Load(), Quarantined: v.quarantined.Load(),
		LocalFailures: v.localFailures.Load(), UploadFailures: v.uploadFailures.Load(), Uploaded: v.uploaded.Load(),
		LastUploadedAt: vaultUnixTime(v.lastUploadedUnix.Load()), LastFailureAt: vaultUnixTime(v.lastFailureUnix.Load()),
	}
}

func vaultUnixTime(value int64) *time.Time {
	if value == 0 {
		return nil
	}
	result := time.Unix(value, 0).UTC()
	return &result
}
