package directoryscanner_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/audrey-morrisette/directoryscanner"
)

// Test for generic sensitive data
var _ = Describe("Directoryscan", func() {
	Describe("Scanning a folder with 8 known findings", func() {
		Context("less than 100 MB in size", func() {
			It("should return 8 findings", func() {
				results, _ := directoryscanner.Scan("./secret")
				Expect(len(results)).To(Equal(8))
			})
		})
	})
})

// Test for credit cards
var _ = Describe("CreditCardScan", func() {
	Describe("Scanning a folder with 2 known Credit Card findings", func() {
		Context("less than 100 MB in size", func() {
			It("should return 2 findings", func() {
				results, _ := directoryscanner.Find("./credit_card", "Credit Card")
				Expect(len(results)).To(Equal(2))
			})
		})
	})
})

// Test for SSN
// var _ = Describe("SSNScan", func() {
// 	Describe("Scanning a folder with 4 known SSN findings", func() {
// 		Context("less than 100 MB in size", func() {
// 			It("should return 4 findings", func() {
// 				results1, _ := directoryscanner.Find("./secret", "SSN")
// 				//fmt.Println("results", len(results))
// 				Expect(len(results1)).To(Equal(2))
// 			})
// 		})
// 	})
// })
