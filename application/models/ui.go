package models

type UIoptions struct {
	Domain                string
	CanContact, CanSignup bool
}

func UIOptions(domain string, contact, signup bool) UIoptions {
	return UIoptions{
		Domain:     domain,
		CanContact: contact,
		CanSignup:  signup,
	}
}
