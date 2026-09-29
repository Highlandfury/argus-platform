package spool

import (
	"fmt"
	"os"
	"path/filepath"
)

// makeSpaceLocked enforces spool_max_bytes (SPEC §10.3): drop the oldest
// segment (acked or not), account every dropped record, and advance the
// watermark past the dropped sequences — they can never be acked, so the
// contiguous-ack bookkeeping must not stall on them. If space still cannot be
// made, ErrSpoolFull is returned and the spool is marked degraded (the caller
// parks the producer). Data is never dropped silently: dropped_records_total
// and a loud log entry record every event.
func (s *Spool) makeSpaceLocked(need int64) error {
	droppedAny := false
	for s.totalBytesLocked()+need > s.maxBytes {
		if len(s.segs) == 0 {
			return ErrSpoolFull
		}
		seg := s.segs[0]
		if s.active != nil && s.active.path == seg.path {
			_ = s.active.close()
			s.active = nil
		}
		if err := os.Remove(seg.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("spool: drop oldest segment: %w", err)
		}
		s.segs = s.segs[1:]
		s.dropped += seg.records
		if seg.lastSeq > s.ackedSeq {
			s.ackedSeq = seg.lastSeq
		}
		droppedAny = true
		s.warnf("spool capacity exceeded: dropped oldest segment",
			"segment", filepath.Base(seg.path),
			"records", seg.records,
			"dropped_records_total", s.dropped,
			"acked_seq", s.ackedSeq)
	}
	if droppedAny {
		s.maybePersistStateLocked(true)
	}
	return nil
}
