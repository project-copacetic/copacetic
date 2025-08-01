package tui

import (
	"bytes"
	"testing"
)

func TestNewDisplay(t *testing.T) {
	tests := []struct {
		name      string
		debugMode bool
		wantType  string
	}{
		{
			name:      "debug mode uses progressui",
			debugMode: true,
			wantType:  "*progressui.Display",
		},
		{
			name:      "normal mode uses progrock", 
			debugMode: false,
			wantType:  "*tui.progrockDisplay",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			display, err := NewDisplay(&buf, tt.debugMode)
			if err != nil {
				t.Fatalf("NewDisplay() error = %v", err)
			}
			if display == nil {
				t.Fatal("NewDisplay() returned nil display")
			}
			
			// Basic type checking
			switch tt.debugMode {
			case true:
				// In debug mode, should get progressui.Display
				if _, ok := display.(Display); !ok {
					t.Error("Expected Display interface")
				}
			case false:
				// In normal mode, should get our progrock display
				if _, ok := display.(*progrockDisplay); !ok {
					t.Error("Expected progrockDisplay")
				}
			}
		})
	}
}

func TestProgrockDisplayCreation(t *testing.T) {
	var buf bytes.Buffer
	display, err := NewProgrockDisplay(&buf)
	if err != nil {
		t.Fatalf("NewProgrockDisplay() error = %v", err)
	}
	
	progrockDisp, ok := display.(*progrockDisplay)
	if !ok {
		t.Fatal("Expected *progrockDisplay")
	}
	
	if progrockDisp.tape == nil {
		t.Error("Expected tape to be initialized")
	}
	if progrockDisp.ui == nil {
		t.Error("Expected ui to be initialized")
	}
	if progrockDisp.rec == nil {
		t.Error("Expected recorder to be initialized")
	}
}