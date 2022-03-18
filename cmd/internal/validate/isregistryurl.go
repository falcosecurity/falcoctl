package validate

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"net/url"
)

func isRegistryURL(fl validator.FieldLevel) bool {
	myUrl := fl.Field()
	_, err := url.ParseRequestURI(myUrl.String())
	if err != nil {
		panic(fmt.Sprintf("Bad field type %T", myUrl.Interface()))
	}
	return true
}
