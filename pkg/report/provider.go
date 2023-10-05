package report

import (
	"encoding/json"
	"fmt"
)

func RunProvider(imageReport string) ([]byte, error) {
	// Initialize the parser
	trivyParser := NewTrivyParser()

	report, err := trivyParser.Parse(imageReport)
	if err != nil {
		fmt.Printf("Error scanning image: %v\n", err)
		return nil, err
	}

	// Serialize the standardized report and print it to stdout
	reportBytes, err := json.Marshal(report)
	if err != nil {
		fmt.Printf("Error serializing report: %v\n", err)
		return nil, err
	}

	return reportBytes, nil
}
