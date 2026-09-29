// Package spool implements the collector's durable segmented WAL (SPEC §10):
// records are framed [u32 len][u32 crc32c(crc32c Castagnoli)][payload] where
// payload is the exact protobuf(MetricBatch) that will be sent on the wire.
// The network is never in the producer's write path.
package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	// MaxSegmentBytes seals a segment (SPEC §10.1: 8 MiB max each).
	MaxSegmentBytes = 8 << 20
	recordHeaderLen = 8
	// maxRecordPayload matches the gRPC message cap (16 MiB).
	maxRecordPayload = 16 << 20

	segmentPrefix    = "seg-"
	segmentSuffix    = ".wal"
	quarantineSuffix = ".corrupt"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Errors surfaced by the spool.
var (
	ErrCorruptRecord = errors.New("spool: corrupt record")
	ErrTornTail      = errors.New("spool: torn tail")
	ErrSpoolFull     = errors.New("spool: capacity exceeded and nothing droppable")
	ErrEmptyBatch    = errors.New("spool: refusing to append an empty batch")
)

// encodeRecord frames one payload: [u32 len][u32 crc32c][payload].
func encodeRecord(payload []byte) []byte {
	rec := make([]byte, recordHeaderLen+len(payload))
	binary.BigEndian.PutUint32(rec[0:4], uint32(len(payload))) //nolint:gosec // callers enforce maxRecordPayload
	binary.BigEndian.PutUint32(rec[4:8], crc32.Checksum(payload, crcTable))
	copy(rec[recordHeaderLen:], payload)
	return rec
}

// readRecord reads one framed record from the current position of f.
// consumed reports how many bytes were consumed (for recovery offsets):
// on success the full record; on ErrCorruptRecord the header only; on
// ErrTornTail nothing (the caller seeks back).
func readRecord(f *os.File) (payload []byte, consumed int64, err error) {
	header := make([]byte, recordHeaderLen)
	n, err := io.ReadFull(f, header)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, io.EOF // clean end or torn header; indistinguishable at EOF
		}
		return nil, 0, err
	}
	_ = n
	length := binary.BigEndian.Uint32(header[0:4])
	if length == 0 || length > maxRecordPayload {
		return nil, recordHeaderLen, ErrCorruptRecord
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(f, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, 0, ErrTornTail
		}
		return nil, 0, err
	}
	want := binary.BigEndian.Uint32(header[4:8])
	if crc32.Checksum(payload, crcTable) != want {
		return nil, recordHeaderLen + int64(length), ErrCorruptRecord
	}
	return payload, recordHeaderLen + int64(length), nil
}

// segmentWriter appends framed records to one segment file.
type segmentWriter struct {
	path     string
	f        *os.File
	size     int64
	firstSeq int64
}

func segmentPath(dir string, firstSeq int64) string {
	return filepath.Join(dir, fmt.Sprintf("%s%09d%s", segmentPrefix, firstSeq, segmentSuffix))
}

func createSegment(dir string, firstSeq int64) (*segmentWriter, error) {
	path := segmentPath(dir, firstSeq)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // path built from the spool dir + sequence
	if err != nil {
		return nil, fmt.Errorf("spool: create segment: %w", err)
	}
	return &segmentWriter{path: path, f: f, firstSeq: firstSeq}, nil
}

func appendSegment(path string) (*segmentWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // segment path from the configured spool dir
	if err != nil {
		return nil, fmt.Errorf("spool: open segment: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("spool: stat segment: %w", err)
	}
	return &segmentWriter{path: path, f: f, size: info.Size(), firstSeq: segmentSeq(filepath.Base(path))}, nil
}

func (w *segmentWriter) appendRecord(rec []byte) error {
	n, err := w.f.Write(rec)
	w.size += int64(n)
	if err != nil {
		return fmt.Errorf("spool: append record: %w", err)
	}
	return nil
}

func (w *segmentWriter) sync() error {
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("spool: fsync: %w", err)
	}
	return nil
}

func (w *segmentWriter) close() error { return w.f.Close() }

// listSegments returns sorted seg-*.wal paths (quarantined files excluded).
func listSegments(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("spool: read dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, segmentPrefix) && strings.HasSuffix(name, segmentSuffix) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	sort.Slice(out, func(i, j int) bool { return segmentSeq(filepath.Base(out[i])) < segmentSeq(filepath.Base(out[j])) })
	return out, nil
}

func segmentSeq(name string) int64 {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(name, segmentPrefix), segmentSuffix)
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 1<<62 - 1 // sort unparsable names last
	}
	return n
}
