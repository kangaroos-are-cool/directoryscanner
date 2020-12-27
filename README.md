# directoryscanner
[![Go Report Card](https://goreportcard.com/badge/github.com/audrey-morrisette/directoryscanner)](https://goreportcard.com/report/github.com/audrey-morrisette/directoryscanner) ![Go](https://github.com/audrey-morrisette/directoryscanner/workflows/Go/badge.svg) [![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/Naereen/StrapDown.js/blob/master/LICENSE)


**A simple go module for scanning directories for sensitive information (or really anything you want)**

## How to Use

```
import ds "github.com/audrey-morrisette/directoryscanner"
...
ds.Scan(".")
```

`Scan()` returns a slice of strings containing all findings from the given directory

## TODO:
- [ ] Add simpler way to add new items to scan for
- [ ] Performance Improvements
