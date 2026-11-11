package stationlink

import "time"

// SetStreamSessionLimits sets the streaming session bounds new admissions
// take, for a test, and returns what restores them.
func SetStreamSessionLimits(perCaller, total int) func() {
	oldPer, oldTotal := defaultSessionsPerCaller, defaultSessions
	defaultSessionsPerCaller, defaultSessions = perCaller, total
	return func() { defaultSessionsPerCaller, defaultSessions = oldPer, oldTotal }
}

// SetStreamInboxBytes sets a stream's inbox bound, for a test.
func SetStreamInboxBytes(n int) func() {
	old := streamInbox
	streamInbox = n
	return func() { streamInbox = old }
}

// SetStreamOpenWait sets how long an accepted stream has to deliver its
// STREAM_OPEN, for a test.
func SetStreamOpenWait(d time.Duration) func() {
	old := streamOpenWait
	streamOpenWait = d
	return func() { streamOpenWait = old }
}

// SetRegisterAckTimeout sets how long Serve and Subscribe wait for the
// station's REGISTER_ACK, for a test.
func SetRegisterAckTimeout(d time.Duration) func() {
	old := registerAckTimeout
	registerAckTimeout = d
	return func() { registerAckTimeout = old }
}

// EndLink ends l with err, as the link's own ending paths do, for a test that
// needs a chosen ending without racing the transport's close (macula-go#75).
func EndLink(l *Link, err error) { l.end(err) }
