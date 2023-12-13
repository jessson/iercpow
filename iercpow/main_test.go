package main

import (
	"fmt"
	"testing"
	"time"
)

func TestPrinf(t *testing.T) {
	fmt.Printf("%d", time.Now().UnixMilli())
}
