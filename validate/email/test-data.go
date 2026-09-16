
// Validate :: Email :: Test Data
// (c) 2026-present, unix-world.org
// r.20260910.2358

package validate_email_address


//-----


func TestData() []string {
	//--
	arr := []string{
		`joe@local`,
		`johndoe@email.eml`,
		`JohnDoe@email.eml`,
		`JOHNDOE@email.eml`,
		`johndoe@Email.eml`,
		`johndoe@Email.Eml`,
		`JOHNDOE@EMAIL.eml`,
		`JOHNDOE@EMAIL.Eml`,
		`JOHNDOE@EMAIL.EML`,
		"john.-_!#$%&'*+/=?^`{|}~doe@email.eml",
		`john±doe@email.eml`,
		`john§doe@email.eml`,
	}
	//--
	return arr
	//--
} //END FUNCTION


func TestInvalidData() []string {
	//--
	arr := []string{
		`john(doe)@email.eml`,
		`john[doe]@email.eml`,
		`john<doe>@email.eml`,
		`john doe@email.eml`,
		`john"doe"@email.eml`,
		`john\\doe@email.eml`,
	}
	//--
	return arr
	//--
} //END FUNCTION


//-----


// #end
