package output

import (
	"encoding/json"
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

type JOutput struct {
	// SourceMetadata contains source-specific contextual information.
	SourceMetadata *source_metadatapb.MetaData
	// SourceID is the ID of the source that the API uses to map secrets to specific sources.
	SourceID int64
	// SourceType is the type of Source.
	SourceType sourcespb.SourceType
	// SourceName is the name of the Source.
	SourceName string
	// DetectorType is the type of Detector.
	DetectorType detectorspb.DetectorType
	// DetectorName is the string name of the DetectorType.
	DetectorName string
	// DecoderName is the string name of the DecoderType.
	DecoderName string
	Verified    bool
	// Raw contains the raw secret data.
	Raw string
	// RawV2 contains the raw secret identifier that is a combination of both the ID and the secret.
	// This is used for secrets that are multi part and could have the same ID. Ex: AWS credentials
	RawV2 string
	// Redacted contains the redacted version of the raw secret identification data for display purposes.
	// A secret ID should be used if available.
	Redacted       string
	ExtraData      map[string]string
	StructuredData *detectorspb.StructuredData
}

func DumpProperJson(r chan detectors.ResultWithMetadata) error {
	var jResult []*JOutput

	for x := range r {
		jResult = append(jResult, CreateJObject(&x))
	}

	out, err := json.Marshal(jResult)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}
	fmt.Println(string(out))

	return nil
}

func CreateJObject(r *detectors.ResultWithMetadata) *JOutput {
	tmp := &JOutput{}
	tmp.SourceMetadata = r.SourceMetadata
	tmp.SourceID = r.SourceID
	tmp.SourceType = r.SourceType
	tmp.SourceName = r.SourceName
	tmp.DetectorType = r.DetectorType
	tmp.DetectorName = r.DetectorType.String()
	tmp.DecoderName = r.DecoderType.String()
	tmp.Verified = r.Verified
	tmp.Raw = string(r.Raw)
	tmp.RawV2 = string(r.RawV2)
	tmp.Redacted = r.Redacted
	tmp.ExtraData = r.ExtraData
	tmp.StructuredData = r.StructuredData

	return tmp
}
