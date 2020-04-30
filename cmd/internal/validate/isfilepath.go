package validate

import (
	"fmt"
	"os"
	"reflect"

	"github.com/go-playground/validator/v10"
)

func isFilePath(fl validator.FieldLevel) bool {
	field := fl.Field()

	switch field.Kind() {
	case reflect.String:
		fileInfo, err := os.Stat(field.String())
		if err != nil {
			if !os.IsNotExist(err) {
				return false
			}
			return true
		}

		return !fileInfo.IsDir()
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
