package directoryscanner_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/audrey-morrisette/directoryscanner"
)

var _ = Describe("Directoryscan", func() {
	Describe("Scanning a folder with 8 known findings", func() {
		Context("less than 100 MB in size", func() {
			It("should return 8 findings", func() {
				results, _ := directoryscanner.Dig("./secret")
				Expect(len(results)).To(Equal(8))
			})
		})
	})
})
