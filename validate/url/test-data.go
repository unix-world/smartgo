
// Validate :: URL :: Test Data
// (c) 2026-present, unix-world.org
// r.20260910.2358

package validate_url


//-----


func TestData() []string {
	//--
	arr := []string{
		`http://localhost`,
		`https://localhost`,
		`http://localhost:80`,
		`https://localhost:443`,
		`http://localhost:8080`,
		`https://localhost:8443`,
		`http://example.com/`,
		`https://example.com/`,
		`http://example.com:1080/`,
		`https://example.com:1443/`,
		`http://example.com:7080/`,
		`https://example.com:7443/`,
		`http://example.com/segment`,
		`https://example.com/segment`,
		`http://example.com:12080/segment`,
		`https://example.com:12443/segment`,
		`http://example.com:10080/segment`,
		`https://example.com:10443/segment`,
		`http://user:pass@example.com:12080/segment?q=a+b&test=a%20b`,
		`https://user:pass@example.com:12443/segment?q=a+b&test=a%20b`,
		`http://user:pass@example.com:10080/segment?q=a+b&test=a%20b`,
		`https://user:pass@example.com:10443/segment?q=a+b&test=a%20b`,
		`http://www.example.com:12080/segment?q=a+b&test=a%20b#hash-fragment`,
		`https://www.example.com:12443/segment?q=a+b&test=a%20b#hash-fragment`,
		`http://www.example.com:10080/segment?q=a+b&test=a%20b#hash-fragment`,
		`https://www.example.com:10443/segment?q=a+b&test=a%20b#hash-fragment`,
		`http://subdomain.example.com:12080/segment?q=a+b&test=a%20b#!js-action`,
		`https://subdomain.example.com:12443/segment?q=a+b&test=a%20b#!js-action`,
		`http://subdomain.example.com:10080/segment?q=a+b&test=a%20b#!js-action`,
		`https://subdomain.example.com:10443/segment?q=a+b&test=a%20b#!js-action`,
		`//example.com`,
		`//example.com/`,
		`//example.com/index.html`,
	}
	//--
	return arr
	//--
} //END FUNCTION


func TestInvalidData() []string {
	//--
	arr := []string{
		`://example.com`,
		`://example.com/`,
		`://example.com/index.html`,
	}
	//--
	return arr
	//--
} //END FUNCTION


//-----


// #end
