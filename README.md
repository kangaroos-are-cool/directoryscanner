# directoryscanner
**A simple go module for scanning directories for sensitive information (or really anything you want)**

##How to Use

'''
import github.com/audrey-morrisette/directoryscanner
...
directoryscanner.Scan(".")
'''

`Scan()` returns a slice of strings containing all findings from the given directory

##TODO:
- [ ] Add simpler way to add new items to scan for
- [ ] Performance Improvements