package v4

import (
	"crypto/sha256"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/govulners-db/internal/file"
	"github.com/anchore/govulners-db/internal/log"
	"github.com/anchore/govulners-db/pkg/data"
	"github.com/anchore/govulners/govulners/db"
	govulnersDB "github.com/anchore/govulners/govulners/db/v4"
	govulnersDBStore "github.com/anchore/govulners/govulners/db/v4/store"
)

// TODO: add NVDNamespace const to govulners.db package?
const nvdNamespace = "nvd:cpe"

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath string
	store  govulnersDB.Store
}

func NewWriter(directory string, dataAge time.Time) (data.Writer, error) {
	dbPath := path.Join(directory, govulnersDB.VulnerabilityStoreFileName)
	theStore, err := govulnersDBStore.New(dbPath, true)
	if err != nil {
		return nil, fmt.Errorf("unable to create writer: %w", err)
	}

	if err := theStore.SetID(govulnersDB.NewID(dataAge)); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	return &writer{
		dbPath: dbPath,
		store:  theStore,
	}, nil
}

func (w writer) Write(entries ...data.Entry) error {
	for _, entry := range entries {
		if entry.DBSchemaVersion != govulnersDB.SchemaVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", govulnersDB.SchemaVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case govulnersDB.Vulnerability:
			if err := w.store.AddVulnerability(row); err != nil {
				return fmt.Errorf("unable to write vulnerability to store: %w", err)
			}
		case govulnersDB.VulnerabilityMetadata:
			normalizeSeverity(&row, w.store)
			if err := w.store.AddVulnerabilityMetadata(row); err != nil {
				return fmt.Errorf("unable to write vulnerability metadata to store: %w", err)
			}
		case govulnersDB.VulnerabilityMatchExclusion:
			if err := w.store.AddVulnerabilityMatchExclusion(row); err != nil {
				return fmt.Errorf("unable to write vulnerability match exclusion to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

func (w writer) metadata() (*db.Metadata, error) {
	hashStr, err := file.ContentDigest(afero.NewOsFs(), w.dbPath, sha256.New())
	if err != nil {
		return nil, fmt.Errorf("failed to hash database file (%s): %w", w.dbPath, err)
	}

	storeID, err := w.store.GetID()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch store ID: %w", err)
	}

	metadata := db.Metadata{
		Built:    storeID.BuildTimestamp,
		Version:  storeID.SchemaVersion,
		Checksum: "sha256:" + hashStr,
	}
	return &metadata, nil
}

func (w writer) Close() error {
	w.store.Close()
	metadata, err := w.metadata()
	if err != nil {
		return err
	}

	metadataPath := path.Join(filepath.Dir(w.dbPath), db.MetadataFileName)
	if err = metadata.Write(metadataPath); err != nil {
		return err
	}

	log.WithFields("path", w.dbPath).Info("database created")
	log.WithFields("path", metadataPath).Debug("database metadata created")

	return nil
}

func normalizeSeverity(metadata *govulnersDB.VulnerabilityMetadata, reader govulnersDB.VulnerabilityMetadataStoreReader) {
	if metadata.Severity != "" && strings.ToLower(metadata.Severity) != "unknown" {
		return
	}
	if !strings.HasPrefix(strings.ToLower(metadata.ID), "cve") {
		return
	}
	if strings.HasPrefix(metadata.Namespace, nvdNamespace) {
		return
	}
	m, err := reader.GetVulnerabilityMetadata(metadata.ID, nvdNamespace)
	if err != nil {
		log.WithFields("id", metadata.ID, "error", err).Warn("error fetching vulnerability metadata from NVD namespace")
		return
	}
	if m == nil {
		log.WithFields("id", metadata.ID).Debug("unable to find vulnerability metadata from NVD namespace")
		return
	}

	newSeverity := string(data.ParseSeverity(m.Severity))

	log.WithFields("id", metadata.ID, "namespace", metadata.Namespace, "from", metadata.Severity, "to", newSeverity).Trace("overriding irrelevant severity with data from NVD record")

	metadata.Severity = newSeverity
}
