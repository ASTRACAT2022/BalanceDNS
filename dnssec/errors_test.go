package dnssec

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestErrors(t *testing.T) {
	err := MissingDSRecordError{"test"}
	assert.Equal(t, "test", err.RName())
	assert.NotEmpty(t, err.Error())
}
