package bulk

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func mockTagLister(tags []string, err error) func(repo name.Repository) ([]string, error) {
	return func(_ name.Repository) ([]string, error) {
		return tags, err
	}
}

func TestFindTagsByPattern(t *testing.T) {
	allMockTags := []string{"1.10.1", "1.9.5", "1.10.0", "1.10.2", "latest", "1.8.0", "1.10.3-alpine", "1.11.0-beta"}

	repo, _ := name.NewRepository("mock/repo")

	testCases := []struct {
		name      string
		spec      *ImageSpec
		mockTags  []string
		expected  []string
		expectErr bool
	}{
		{
			name: "Simple Pattern Match and Sort",
			spec: &ImageSpec{
				Name: "test",
				Tags: TagStrategy{
					Strategy:        StrategyPattern,
					Pattern:         `^1\.10\.[0-9]+$`,
					compiledPattern: regexp.MustCompile(`^1\.10\.[0-9]+$`),
				},
			},
			mockTags:  allMockTags,
			expected:  []string{"1.10.0", "1.10.1", "1.10.2"},
			expectErr: false,
		},
		{
			name: "Pattern with MaxTags",
			spec: &ImageSpec{
				Name: "test",
				Tags: TagStrategy{
					Strategy:        StrategyPattern,
					Pattern:         `^1\.10\.[0-9]+$`,
					MaxTags:         2,
					compiledPattern: regexp.MustCompile(`^1\.10\.[0-9]+$`),
				},
			},
			mockTags:  allMockTags,
			expected:  []string{"1.10.1", "1.10.2"},
			expectErr: false,
		},
		{
			name: "Pattern with Exclude",
			spec: &ImageSpec{
				Name: "test",
				Tags: TagStrategy{
					Strategy:        StrategyPattern,
					Pattern:         `^1\.10\.[0-9]+$`,
					Exclude:         []string{"1.10.1"},
					compiledPattern: regexp.MustCompile(`^1\.10\.[0-9]+$`),
				},
			},
			mockTags:  allMockTags,
			expected:  []string{"1.10.0", "1.10.2"},
			expectErr: false,
		},
		{
			name: "Pattern with No Semver Matches",
			spec: &ImageSpec{
				Name: "test",
				Tags: TagStrategy{
					Strategy:        StrategyPattern,
					Pattern:         `latest`,
					compiledPattern: regexp.MustCompile("latest"),
				},
			},
			mockTags:  allMockTags,
			expected:  []string{},
			expectErr: false,
		},
		{
			name: "Pattern does not match pre-releases",
			spec: &ImageSpec{
				Name: "test",
				Tags: TagStrategy{
					Strategy:        StrategyPattern,
					Pattern:         `^1\.11\..*$`,
					compiledPattern: regexp.MustCompile(`^1\.11\..*$`),
				},
			},
			mockTags:  allMockTags,
			expected:  []string{},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalLister := listAllTags
			listAllTags = mockTagLister(tc.mockTags, nil)
			defer func() { listAllTags = originalLister }()

			result, err := findTagsByPattern(repo, tc.spec)

			if (err != nil) != tc.expectErr {
				t.Errorf("Expected error: %v, but got: %v", tc.expectErr, err)
			}

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected result %v, but got %v", tc.expected, result)
			}
		})
	}
}

func TestFindTagsByLatest(t *testing.T) {
	allMockTags := []string{"2.1.0", "3.0.0-alpha", "latest", "2.0.0", "2.1.1"}
	repo, _ := name.NewRepository("mock/repo")
	spec := &ImageSpec{Name: "test"}

	originalLister := listAllTags
	listAllTags = mockTagLister(allMockTags, nil)
	defer func() { listAllTags = originalLister }()
	result, err := findTagsByLatest(repo, spec)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	expected := []string{"2.1.1"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected result %v, but got %v", expected, result)
	}
}
