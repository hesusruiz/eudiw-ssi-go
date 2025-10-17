package rendering

import (
	"github.com/hesusruiz/eudiw-ssi-go/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// IsValidEntityStyle validates an entity style descriptor against its known schema
func IsValidEntityStyle(esd EntityStyleDescriptor) error {
	jsonBytes, err := json.Marshal(esd)
	if err != nil {
		return errors.Wrap(err, "marshaling entity style descriptor")
	}
	s, err := schema.LoadSchema(schema.EntityStylesSchema)
	if err != nil {
		return errors.Wrap(err, "getting entity styles schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "entity style not valid against schema")
	}
	return nil
}

// IsValidDisplayMappingObject validates a display mapping object against its known schema
func IsValidDisplayMappingObject(dmo DisplayMappingObject) error {
	jsonBytes, err := json.Marshal(dmo)
	if err != nil {
		return errors.Wrap(err, "marshaling display mapping object")
	}
	s, err := schema.LoadSchema(schema.DisplayMappingObjectSchema)
	if err != nil {
		return errors.Wrap(err, "getting display mapping object schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "display mapping object not valid against schema")
	}
	return nil
}

// IsValidLabeledDisplayMappingObject validates a labeled display mapping object against its known schema
func IsValidLabeledDisplayMappingObject(ldmo LabeledDisplayMappingObject) error {
	jsonBytes, err := json.Marshal(ldmo)
	if err != nil {
		return errors.Wrap(err, "marshaling labeled display mapping object")
	}
	s, err := schema.LoadSchema(schema.LabeledDisplayMappingObjectSchema)
	if err != nil {
		return errors.Wrap(err, "getting labeled display mapping object schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "labeled display mapping object not valid against schema")
	}
	return nil
}
