# directoryscanner
[![Go Report Card](https://goreportcard.com/badge/github.com/audrey-morrisette/directoryscanner)](https://goreportcard.com/report/github.com/audrey-morrisette/directoryscanner) ![Go](https://github.com/audrey-morrisette/directoryscanner/workflows/Go/badge.svg) [![Go Reference](https://pkg.go.dev/badge/github.com/audrey-morrisette/directoryscanner.svg)](https://pkg.go.dev/github.com/audrey-morrisette/directoryscanner) [![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/Naereen/StrapDown.js/blob/master/LICENSE)



**A simple go module for scanning directories for sensitive information (or really anything you want)**

## How to Use

```
import ds "github.com/audrey-morrisette/directoryscanner"
...
ds.Scan(".")
```

`Scan(path string)`  
returns a slice of strings containing all findings from the given directory

`Find(path string, dataTypes ...string)`  
returns a slice of strings containing all the findings specified by the variadic parameter 'dataTypes'

`FindString(path string, strings ...string)`  
returns a slice of strings containing all findings as specified by the variadic parameter 'strings' which can contain any string you like

## TODO:
- [ ] Add simpler way to add new items to scan for
- [ ] Improve Documentation
- [ ] Performance Improvements
