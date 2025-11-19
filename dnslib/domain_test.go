package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDomain(t *testing.T) {
	d := newDomain("www.example.com.")

	// Check the canonical name format
	assert.Equal(t, "www.example.com.", d.name, "Domain name should be canonicalized")

	// Check label indexes (should be in reverse order, including the root level)
	expectedLabels := []int{15, 12, 4, 0} // Positions for "www.example.com", "example.com", "com", and "."
	assert.Equal(t, expectedLabels, d.labelIndexes, "Label indexes should match expected order including the root")
}

func TestCurrent(t *testing.T) {
	d := newDomain("www.example.com.")

	// Initial current should return the root
	assert.Equal(t, ".", d.current(), "Initial current should return root level '.'")

	// Move to next and check the current segment
	d.next()
	assert.Equal(t, "com.", d.current(), "After next, current should return 'com.'")

	// Move to the next segment (example.com)
	d.next()
	assert.Equal(t, "example.com.", d.current(), "After another next, current should return 'example.com.'")

	// Move to the full domain
	d.next()
	assert.Equal(t, "www.example.com.", d.current(), "Final next should return the full domain 'www.example.com.'")

	// If we keep calling next, we should always just get the full domain back.
	d.next()
	assert.Equal(t, "www.example.com.", d.current(), "Final next should return the full domain 'www.example.com.'")
	d.next()
	assert.Equal(t, "www.example.com.", d.current(), "Final next should return the full domain 'www.example.com.'")
	d.next()
	assert.Equal(t, "www.example.com.", d.current(), "Final next should return the full domain 'www.example.com.'")
}

func TestNextAndMore(t *testing.T) {
	d := newDomain("www.example.com.")

	// Test more before moving
	assert.True(t, d.more(), "Expected more() to return true initially")
	assert.False(t, d.last(), "Expected last() to return false initially")

	// Move to each label and check more
	d.next() // com.
	assert.True(t, d.more(), "Expected more() to return true after first next()")
	assert.False(t, d.last(), "Expected last() to return false after second next()")

	d.next() // example.com.
	assert.True(t, d.more(), "Expected more() to return true after second next()")
	assert.False(t, d.last(), "Expected last() to return false after second next()")

	d.next() // full domain www.example.com.
	assert.True(t, d.more(), "Expected more() to return true after third next()")
	assert.True(t, d.last(), "Expected last() to return true after third next()")

	// Note - we expect the full domain to be returned twice.
	d.next() // full domain www.example.com
	assert.True(t, d.more(), "Expected more() to return true after fourth next()")
	assert.True(t, d.last(), "Expected last() to return true after fourth next()")

	// Move past last label (full domain) and check more
	d.next()
	assert.False(t, d.more(), "Expected more() to return false after all labels are traversed")
	assert.True(t, d.last(), "Expected last() to return true after all labels are traversed")

}

func TestWindTo(t *testing.T) {
	d := newDomain("www.example.com.")

	// Valid target
	err := d.windTo("example.com.")
	assert.NoError(t, err, "Expected to find 'example.com.' without error")
	assert.Equal(t, "example.com.", d.current())

	// Reset position
	d.currentIdx = 0

	// Invalid target
	err = d.windTo("nonexistent.example.com.")
	assert.Error(t, err, "Expected error when target is not found")
}

func TestGap(t *testing.T) {
	d := newDomain("www.example.com.")
	d.next()

	// Check gap from current (root) to "example.com."
	expectedGap := []string{"com."}
	gap := d.gap("example.com.")
	require.Equal(t, len(expectedGap), len(gap), "Gap length should match expected")
	assert.Equal(t, expectedGap, gap, "Gap should match expected segments")

	// Gap should be idempotent, so calling it again should yield the same results
	gap = d.gap("example.com.")
	assert.Equal(t, expectedGap, gap, "Gap should be idempotent and return the same result on subsequent calls")
}

func TestGap_NoMissingLabels(t *testing.T) {
	d := newDomain("www.example.com.")

	// Move to "example.com."
	d.next()
	d.next()

	// Attempt to get a gap to a target with fewer labels (com.)
	expectedGap := []string{}
	gap := d.gap("com.")
	require.Equal(t, len(expectedGap), len(gap), "Gap should be empty when target has fewer labels")
	assert.Nil(t, gap, "Gap should be empty when target has fewer labels")

	// Reset to full domain
	d = newDomain("www.example.com.")

	d.next()

	// Attempt to get a gap to the same domain (www.example.com.)
	expectedGap = []string{}
	gap = d.gap("com.")
	require.Equal(t, len(expectedGap), len(gap), "Gap should be empty when target is the same domain")
	assert.Nil(t, gap, "Gap should be empty when target is the same domain")
}

func TestGap_NotSubdomain(t *testing.T) {
	d := newDomain("store.")

	// Move to "example.com."
	d.next()
	d.next()

	// Attempt to get a gap to a target with fewer labels (com.)
	expectedGap := []string{}
	gap := d.gap("xyz.store.")
	require.Equal(t, len(expectedGap), len(gap), "Gap should be empty when target has fewer labels")
	assert.Empty(t, gap, "Gap should be empty when target has fewer labels")

}
