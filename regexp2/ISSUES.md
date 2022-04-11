
# Overlapping Match Fix
https://github.com/dlclark/regexp2/issues/34

Just like in PCRE some expression may cause infinite loops.
This is a known issue with very complex regular expression libraries ...


## The following test results in an infinite loop.

```go
func TestOverlappingMatch(t *testing.T) {
    re := MustCompile(`((?:0*)+?(?:.*)+?)?`, 0)
    match, err := re.FindStringMatch("0\xfd")
    if err != nil {
	t.Fatal(err)
    }
    for match != nil {
	t.Logf("start: %d, length: %d", match.Index, match.Length)
	match, err = re.FindNextMatch(match)
	if err != nil {
	    t.Fatal(err)
	}
    }
}
```

## Fix: Introduce a max recursion limit like in PCRE to avoid infinite loop !

```go
func TestOverlappingMatch(t *testing.T) {
    maxRecursion := 8000000
    re := MustCompile(`((?:0*)+?(?:.*)+?)?`, 0)
    match, err := re.FindStringMatch("0\xfd")
    if err != nil {
	t.Fatal(err)
    }
    for match != nil {
	t.Logf("start: %d, length: %d", match.Index, match.Length)
	match, err = re.FindNextMatch(match)
	if err != nil {
	    t.Fatal(err)
	}
	maxRecursion--
	if(maxRecursion <= 0) {
	    break
	}
    }
}
```

### The above solution is a fix by unixman ... (c) 2022 unix-world.org

