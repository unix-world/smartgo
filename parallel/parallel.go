
// go parallel
// r.20241021.2358
// (c) 2024 unix-world.org

package parallel

import (
	"sync"
)


func ForEach(arr []any, fn func(elem any)) {
	wg := &sync.WaitGroup{} // new wg instance
	wg.Add(len(arr))

	for _, item := range arr {
		go func(el any) {
			defer wg.Done()

			fn(el)
		}(item)
	}

	wg.Wait()
}


func ForEachLimit(arr []any, concurrency uint16, fn func(elem any)) {
	wg := &sync.WaitGroup{} // new wg instance
	wg.Add(len(arr))

	if(concurrency < 1) {
		concurrency = 1
	}
	limiter := make(chan struct{}, concurrency)

	for _, item := range arr {
		limiter <- struct{}{}

		go func(el any) {
			defer wg.Done()

			fn(el)

			<-limiter
		}(item)
	}

	wg.Wait()
}


func Map(arr []any, fn func(elem any) any) []any {
	wg := &sync.WaitGroup{} // new wg instance
	wg.Add(len(arr))

	output := make([]any, len(arr), len(arr))

	for i := range arr {
		go func(index int, el any) {
			defer wg.Done()

			result := fn(el)
			output[index] = result
		}(i, arr[i])
	}

	wg.Wait()

	return output
}


func MapLimit(arr []any, concurrency uint16, fn func(elem any) any) []any {
	wg := &sync.WaitGroup{} // new wg instance
	wg.Add(len(arr))

	if(concurrency < 1) {
		concurrency = 1
	}
	limiter := make(chan struct{}, concurrency)

	output := make([]any, len(arr), len(arr))

	for i := range arr {
		limiter <- struct{}{}

		go func(index int, el any) {
			defer wg.Done()

			result := fn(el)
			output[index] = result

			<-limiter
		}(i, arr[i])
	}

	wg.Wait()

	return output
}


// #end
