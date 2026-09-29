package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// stateFile is the persisted watermark/accounting (state.json, atomic swap).
type stateFile struct {
	AckedSeq            int64 `json:"acked_seq"`
	HighestSeq          int64 `json:"highest_seq"`
	DroppedRecordsTotal int64 `json:"dropped_records_total"`
	CorruptRecordsTotal int64 `json:"corrupt_records_total"`
}

func (s *Spool) statePath() string { return filepath.Join(s.dir, "state.json") }

func (s *Spool) loadStateLocked() error {
	raw, err := os.ReadFile(s.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("spool: read state: %w", err)
	}
	var st stateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		bak := s.statePath() + ".corrupt"
		_ = os.Rename(s.statePath(), bak)
		s.corrupt++
		s.warnf("spool state.json unreadable; quarantined and rebuilt from segments", "path", bak, "error", err)
		return nil
	}
	s.ackedSeq = st.AckedSeq
	s.highestSeq = st.HighestSeq
	s.dropped = st.DroppedRecordsTotal
	s.corrupt = st.CorruptRecordsTotal
	return nil
}

func (s *Spool) saveStateLocked() error {
	st := stateFile{
		AckedSeq:            s.ackedSeq,
		HighestSeq:          s.highestSeq,
		DroppedRecordsTotal: s.dropped,
		CorruptRecordsTotal: s.corrupt,
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("spool: marshal state: %w", err)
	}
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("spool: write state: %w", err)
	}
	if err := os.Rename(tmp, s.statePath()); err != nil {
		return fmt.Errorf("spool: commit state: %w", err)
	}
	s.lastState = time.Now()
	return nil
}

// maybePersistStateLocked throttles state rewrites to once per 250 ms.
func (s *Spool) maybePersistStateLocked(force bool) {
	if !force && time.Since(s.lastState) < 250*time.Millisecond {
		return
	}
	if err := s.saveStateLocked(); err != nil {
		s.warnf("spool state save failed", "error", err)
	}
}

// recover loads state, scans all segments (torn-tail truncation, CRC
// quarantine), purges fully-acked segments, and opens the active writer.
func (s *Spool) recover() error {
	if err := s.loadStateLocked(); err != nil {
		return err
	}
	files, err := listSegments(s.dir)
	if err != nil {
		return err
	}
	for i, path := range files {
		isLast := i == len(files)-1
		if err := s.scanSegment(path, isLast); err != nil {
			return err
		}
	}
	s.purgeLocked()
	if len(s.segs) > 0 {
		if last := s.segs[len(s.segs)-1].lastSeq; last > s.highestSeq {
			s.highestSeq = last
		}
	}
	if s.ackedSeq > s.highestSeq {
		s.ackedSeq = s.highestSeq
	}
	if len(s.segs) > 0 {
		w, err := appendSegment(s.segs[len(s.segs)-1].path)
		if err != nil {
			return err
		}
		s.active = w
	}
	if err := s.saveStateLocked(); err != nil {
		return err
	}
	stats := s.Stats()
	s.infof("spool recovered",
		"segments", len(s.segs),
		"records", stats.Records,
		"bytes", stats.Bytes,
		"acked_seq", stats.AckedSeq,
		"highest_seq", stats.HighestSeq,
		"dropped", stats.DroppedRecordsTotal,
		"corrupt", stats.CorruptRecordsTotal)
	return nil
}

// scanSegment validates one segment. Corruption in the last (active) segment
// truncates the torn tail; corruption in a sealed segment quarantines the file
// from the first bad record on while preserving the readable prefix
// (SPEC §10.2) — nothing is silently discarded. File handles are closed before
// any truncate/rename so the behavior is identical on POSIX and Windows.
func (s *Spool) scanSegment(path string, isLast bool) error {
	f, err := os.Open(path) //nolint:gosec // segment path from the configured spool dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("spool: open segment: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("spool: stat segment: %w", err)
	}

	meta := &segMeta{path: path, firstSeq: segmentSeq(filepath.Base(path)), bytes: info.Size()}
	offset := int64(0)
	action := ""
	for {
		payload, consumed, rerr := readRecord(f)
		switch {
		case rerr == nil:
			offset += consumed
			b, derr := batchFromPayload(payload)
			if derr != nil {
				if isLast {
					action = "truncate"
				} else {
					action = "quarantine"
				}
				break
			}
			if b.Seq > meta.lastSeq {
				meta.lastSeq = b.Seq
			}
			meta.records++
		case errors.Is(rerr, io.EOF):
			if isLast && offset < info.Size() {
				action = "truncate"
			} else {
				_ = f.Close()
				s.segs = append(s.segs, meta)
				return nil
			}
		case errors.Is(rerr, ErrTornTail):
			if isLast {
				action = "truncate"
			} else {
				action = "quarantine"
			}
		case errors.Is(rerr, ErrCorruptRecord):
			if isLast {
				action = "truncate"
			} else {
				action = "quarantine"
			}
		default:
			_ = f.Close()
			return fmt.Errorf("spool: scan segment: %w", rerr)
		}
		if action != "" {
			break
		}
	}
	_ = f.Close()
	switch action {
	case "truncate":
		return s.truncateTail(path, offset, meta)
	case "quarantine":
		return s.quarantineTail(path, offset, meta)
	default:
		s.segs = append(s.segs, meta)
		return nil
	}
}

// truncateTail removes a torn/invalid tail in place (safe for the last
// segment: every record before offset is intact).
func (s *Spool) truncateTail(path string, offset int64, meta *segMeta) error {
	if err := os.Truncate(path, offset); err != nil {
		return fmt.Errorf("spool: truncate torn tail: %w", err)
	}
	if f, err := os.OpenFile(path, os.O_RDWR, 0o600); err == nil { //nolint:gosec // segment path from the configured spool dir
		_ = f.Sync()
		_ = f.Close()
	}
	meta.bytes = offset
	s.corrupt++
	s.warnf("spool torn/corrupt tail truncated", "segment", filepath.Base(path), "valid_bytes", offset, "corrupt_total", s.corrupt)
	s.segs = append(s.segs, meta)
	return nil
}

// quarantineTail preserves the readable prefix of a sealed segment in place
// and renames the original file (with the bad region) to *.corrupt so the
// bytes remain operator-visible.
func (s *Spool) quarantineTail(path string, goodEnd int64, meta *segMeta) error {
	prefix, err := os.ReadFile(path) //nolint:gosec // segment path from the configured spool dir
	if err != nil {
		return fmt.Errorf("spool: read for quarantine: %w", err)
	}
	if goodEnd > int64(len(prefix)) {
		goodEnd = int64(len(prefix))
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, prefix[:goodEnd], 0o600); err != nil { //nolint:gosec // temp path derived from the segment path
		return fmt.Errorf("spool: write quarantine temp: %w", err)
	}
	if err := os.Rename(path, fmt.Sprintf("%s%s-%d", path, quarantineSuffix, time.Now().Unix())); err != nil {
		return fmt.Errorf("spool: quarantine segment: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("spool: restore segment prefix: %w", err)
	}
	meta.bytes = goodEnd
	s.corrupt++
	s.warnf("spool segment quarantined from first bad record; readable prefix preserved",
		"segment", filepath.Base(path), "valid_bytes", goodEnd, "corrupt_total", s.corrupt)
	s.segs = append(s.segs, meta)
	return nil
}

// Reader sequentially reads batches from the spool from the current watermark,
// forcing the group fsync before a batch becomes send-eligible. It refreshes
// its segment view when it runs out: sealed/new segments appear (and fully
// acked ones disappear) while a long-lived stream session is running.
type Reader struct {
	sp       *Spool
	files    []string
	idx      int
	f        *os.File
	lastPath string // last segment opened (lexical cursor across refreshes)
}

// Reader returns a new sequential reader over the spool's segments.
func (s *Spool) Reader() (*Reader, error) {
	files, err := listSegments(s.dir)
	if err != nil {
		return nil, err
	}
	return &Reader{sp: s, files: files}, nil
}

// Next returns the next batch after the watermark, or (nil, nil) when idle.
func (r *Reader) Next() (*Batch, error) {
	if err := r.sp.ForceSync(); err != nil {
		return nil, err
	}
	for {
		if r.f == nil {
			if r.idx >= len(r.files) {
				// Refresh the view: new segments may have been created (and
				// purged ones removed) since the last refresh. Zero-padded
				// names sort chronologically, so resuming past lastPath is
				// exact and never re-reads processed segments.
				files, err := listSegments(r.sp.dir)
				if err != nil {
					return nil, err
				}
				r.files = files
				r.idx = 0
				for r.idx < len(r.files) && r.files[r.idx] <= r.lastPath {
					r.idx++
				}
				if r.idx >= len(r.files) {
					return nil, nil
				}
			}
			path := r.files[r.idx]
			r.idx++
			f, err := os.Open(path) //nolint:gosec // segment path from the configured spool dir
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, err
			}
			r.f = f
			r.lastPath = path
		}
		pos, err := r.f.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, err
		}
		payload, _, err := readRecord(r.f)
		switch {
		case err == nil:
			b, derr := batchFromPayload(payload)
			if derr != nil {
				r.sp.warnf("spool reader found undecodable record; skipping remainder", "segment", r.f.Name(), "error", derr)
				r.closeCurrent()
				continue
			}
			if b.Seq <= r.sp.Watermark() {
				continue // retired (acked or dropped) while this reader ran
			}
			return b, nil
		case errors.Is(err, io.EOF):
			r.closeCurrent()
		case errors.Is(err, ErrTornTail):
			// Active segment may still be appended to: rewind and go idle.
			if _, err := r.f.Seek(pos, io.SeekStart); err != nil {
				return nil, err
			}
			return nil, nil
		case errors.Is(err, ErrCorruptRecord):
			r.sp.warnf("spool reader hit a corrupt record; skipping segment remainder", "segment", r.f.Name())
			r.closeCurrent()
		default:
			return nil, err
		}
	}
}

func (r *Reader) closeCurrent() {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
}

// Close releases the reader's file handle.
func (r *Reader) Close() {
	r.closeCurrent()
}
