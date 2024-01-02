# progressbar

A very simple thread-safe progress bar which should work on every OS without problems.

## Based on
github.com/schollz/progressbar/v2

## Usage 

### Basic usage

```golang
bar := progressbar.New(100)
for i := 0; i < 100; i++ {
    bar.Add(1)
    time.Sleep(10 * time.Millisecond)
}
```

The times at the end show the elapsed time and the remaining time, respectively.

### Long running processes

For long running processes, you might want to render from a 0% state.

```golang
// Renders the bar right on construction
bar := progressbar.NewOptions(100, progressbar.OptionSetRenderBlankState(true))
```

Alternatively, when you want to delay rendering, but still want to render a 0% state
```golang
bar := progressbar.NewOptions(100)

// Render the current state, which is 0% in this case
bar.RenderBlank()

// Emulate work
for i := 0; i < 10; i++ {
    time.Sleep(10 * time.Minute)
    bar.Add(10)
}
```

### Use a custom writer

The default writer is standard output (os.Stdout), but you can set it to whatever satisfies io.Writer.
```golang
bar := NewOptions(
    10,
    OptionSetTheme(Theme{Saucer: "#", SaucerPadding: "-", BarStart: ">", BarEnd: "<"}),
    OptionSetWidth(10),
    OptionSetWriter(&buf),
)

bar.Add(5)
result := strings.TrimSpace(buf.String())

// Result equals:
// 50% >#####-----< [0s:0s]

```

### Progress for I/O operations

The `progressbar` implements an `io.Writer` so it can automatically detect the number of bytes written to a stream, so you can use it as a progressbar for an `io.Reader`.

```golang
urlToGet := "https://url/large-file.zip"
req, _ := http.NewRequest("GET", urlToGet, nil)
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var out io.Writer
f, _ := os.OpenFile("large-file.zip", os.O_CREATE|os.O_WRONLY, 0644)
out = f
defer f.Close()

bar := progressbar.NewOptions(
    int(resp.ContentLength), 
    progressbar.OptionSetBytes(int(resp.ContentLength)),
)
out = io.MultiWriter(out, bar)
io.Copy(out, resp.Body)
```

See the tests for another example.

### Changing max value

The `progressbar` implements `ChangeMax` and `ChangeMax64` functions to change the max value of the progress bar.

```golang
bar := progressbar.New(100)
bar.ChangeMax(200) // Change the max of the progress bar to 200, not 100
```

You can also use `ChangeMax64` to minimize casting in the library.
See the tests for another example.

### Displaying Total Increment Over Predicted Time

By default the progress bar will attempt to predict the remaining amount of time left. This can be change to 
just show the current increment over the total maximum amount set for the progress bar. Do this by using the
`OptionSetPredictTime` option during progress bar creation.

```golang
bar := progressbar.NewOptions(100, progressbar.OptionSetPredictTime(false))
bar.Add(20)
```

## Contributing

Pull requests are welcome. Feel free to...

- Revise documentation
- Add new features
- Fix bugs
- Suggest improvements

## License

MIT

