package directoryscanner_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestDirectoryscanner(t *testing.T) {

	RegisterFailHandler(Fail)
	RunSpecs(t, "Directoryscanner Suite")

}
