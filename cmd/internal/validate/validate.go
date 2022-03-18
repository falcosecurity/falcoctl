package validate

import (
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

// V is the validator single instance.
//
// It is a singleton so to cache the structs info.
var V *validator.Validate

// T is the universal translator for validatiors.
var T ut.Translator

func init() {
	V = validator.New()

	// Register a function to get the field name from "name" tags.
	V.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("name"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	V.RegisterValidation("logrus", isLogrusLevel)
	V.RegisterValidation("filepath", isFilePath)
	V.RegisterValidation("registryurl", isRegistryURL)

	eng := en.New()
	uni := ut.New(eng, eng)
	T, _ = uni.GetTranslator("en")
	en_translations.RegisterDefaultTranslations(V, T)

	V.RegisterTranslation(
		"filepath",
		T,
		func(ut ut.Translator) error {
			return ut.Add("filepath", "{0} must be a valid file path", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("filepath", fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"logrus",
		T,
		func(ut ut.Translator) error {
			return ut.Add("logrus", "{0} must be a valid logrus level", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("logrus", fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"registryurl",
		T,
		func(ut ut.Translator) error {
			return ut.Add("registryurl", "{0} must be a valid URL", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("registryurl", fe.Field())

			return t
		},
	)
}
